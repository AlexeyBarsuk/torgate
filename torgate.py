#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import os
import re
import argparse
import uuid
import aiofile
import config
import asyncio
import copy
import hashlib

import logging
import coloredlogs
coloredlogs.install(level=config.LOGLEVEL, fmt='%(asctime)s - %(levelname)s - %(message)s')

# костанты
TOR_OUT_FILE = "tor.out"
PROXIES_FILE_REFRESH_INTERVAL = 2


async def start_tor_pipe(interface, port, control_port,  tor_executable_path, removable_temp_dir):
    tor_process_working_dir = removable_temp_dir + '/torrc%d/' % (port,)
    config_filename = tor_process_working_dir + "torrc.conf"
    out_filename = tor_process_working_dir + TOR_OUT_FILE

    config_content = """
            SocksPort %s:%d
            ControlPort %d
            DataDirectory %s
            HardwareAccel 1
            SocksTimeout 5
            # CircuitBuildTimeout 240
            MaxClientCircuitsPending 512
        """ % (
        interface,
        port,
        control_port,
        tor_process_working_dir
    )

    try:
        logging.info("Starting tor listener on %s:%d" % (interface, port, ))

        # создаем задержку при запуске процессов, чтобы они вcе разом не
        # послали SIGCHLD и не переполнили пайп event loopа
        await asyncio.sleep(random.randrange(5000)/1000)

        process = await asyncio.create_subprocess_shell("mkdir -p " + tor_process_working_dir)
        await process.wait()

        async with aiofile.AIOFile(config_filename, 'w') as fw:
            await fw.write(config_content)
            await fw.fsync()

        process = await asyncio.create_subprocess_shell(
            "%s -f %s > %s" % (
                tor_executable_path,
                config_filename,
                out_filename,),
            env=dict(os.environ)
        )
        await process.wait()

    except asyncio.CancelledError:
        logging.info("Exiting tor listener on %s:%s" % (interface, port, ))
        return
    except Exception as e:
        logging.error("Something wrong with tor listener %s:%s. Exception = %s" % (interface, port, e))


async def check_proxies_and_write_file_forever(removable_temp_dir, should_check_connections=True):
    logging.debug("Checking connections from %s" % (removable_temp_dir,))

    async def get_proxy_from_tor_out_file(out_file_name):
        out_file_contents = None
        try:
            async with aiofile.AIOFile(out_file_name, 'r') as fr:
                out_file_contents = await fr.read()
        except Exception as e:
            logging.warning("Can not read tor out file %s. Exception=%s" % (out_file_name, e))
            return None

        # если загрузилась нода
        if re.search("Bootstrapped 100\%", out_file_contents, re.MULTILINE):
            config_str = tuple(re.findall("Opening Socks listener on.*", out_file_contents, re.MULTILINE))
            if config_str:
                return config_str[0].split(" ")[4]
            else:
                logging.error("Can not find proxy host and port in tor out file %s", (out_file_name,))
                return None
        else:
            logging.debug("Tor in %s in not bootstrapped yet" % (out_file_name,))

    try:
        while True:
            # читаем все папки из темповой папки
            dirs = os.listdir(removable_temp_dir)

            # достаем прокси
            promises = [get_proxy_from_tor_out_file(removable_temp_dir + "/" + tor_dir + "/" + TOR_OUT_FILE) for tor_dir in dirs]
            proxies = await asyncio.gather(*promises)

            # убираем пустышки
            proxies = list(filter(lambda x: x is not None, copy.deepcopy(proxies)))

            # если нужно проверять подключенность
            if should_check_connections:
                connected_proxies = []
                promises = [check_direct_connection(proxy.split(':')[0], int(proxy.split(':')[1])) for proxy in proxies]
                check_connections_results = await asyncio.gather(*promises)
                for i in range(0, len(check_connections_results)):
                    if check_connections_results[i]:
                        connected_proxies.append(proxies[i])
                proxies = connected_proxies

            # Считаем хэш содержимого файла, если он есть
            current_contents = ""
            try:
                async with aiofile.AIOFile(config.PROXIES_FILENAME, 'r') as fr:
                    current_contents = await fr.read()
            except FileNotFoundError:
                pass

            # создаем новое содержимое файла
            proxies_file_contents = ""
            for host_port_str in proxies:
                proxies_file_contents += "%s\n" % (host_port_str,)

            # пишем прокси в файл если содержимые разные
            if hashlib.md5(current_contents.encode('utf-8')).hexdigest() != hashlib.md5(proxies_file_contents.encode('utf-8')).hexdigest():
                async with aiofile.AIOFile(config.PROXIES_FILENAME, 'w') as fw:
                    await fw.write(proxies_file_contents)
                    await fw.fsync()
                logging.info("%s good proxies are written to %s" % (len(proxies), config.PROXIES_FILENAME))
            else:
                logging.info("%s good proxies are in %s" % (len(proxies), config.PROXIES_FILENAME))
            # спим
            await asyncio.sleep(PROXIES_FILE_REFRESH_INTERVAL)

    except asyncio.CancelledError:
        # останавливаемся в случае ctrl+c
        pass


async def check_direct_connection(host, port):
    try:
        reader, writer = await asyncio.open_connection(host, port)
        writer.close()
        return True
    except Exception as e:
        logging.debug("Connection to %s:%s failed. Exception=%s" % (host, port, e))
        return False


async def main():
    parser = argparse.ArgumentParser(
        description='Tor proxy set.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        '--count',
        action="store",
        type=int,
        help="Number of tor processes (number of proxy servers)",
        default=config.PROXIES_COUNT)
    parser.add_argument(
        '--out_filename',
        action="store",
        type=str,
        help="Out file with proxies host:port list",
        default=config.PROXIES_FILENAME)
    parser.add_argument(
        '--interface',
        action="store",
        type=str,
        help="Local interface address to open ports on it",
        default=config.LISTEN_INTERFACE)
    parser.add_argument(
        '--min_port',
        action="store",
        type=int,
        help="Minimal port in range",
        default=config.PORT_RANGE_START)
    parser.add_argument(
        '--max_port',
        action="store",
        type=int,
        help="Maximal port in range",
        default=config.PORT_RANGE_END)
    parser.add_argument(
        '--temp_dir',
        action="store",
        type=str,
        help="Directory to save working data",
        default=config.TEMP_DIR_PATH)
    parser.add_argument(
        '--tor_binary',
        action="store",
        type=str,
        help="Tor executable path",
        default=config.TOR_EXECUTABLE_PATH)

    # парсим
    try:
        args = parser.parse_args()
    except Exception as e:
        logging.error("Parse command line args error=%s" % (e,))
        return

    # проверки
    if args.min_port > args.max_port:
        logging.error("Wrong port range[%s:%s]" % (args.min_port, args.max_port))
        return

    if args.max_port - args.min_port < args.count * 2:
        logging.error("Port range[%s:%s] is not enough for %s proxies. You need at least %s port range width" % (
            args.min_port,
            args.max_port,
            args.count,
            args.count * 2))
        return

    logging.info("Starting tor big proxy for %d ports. Address is %s. Proxy file is %s" % (
        args.count,
        args.interface,
        args.out_filename))

    # создаем временную папку
    tor_removable_dir_path = args.temp_dir + "/_torgate_" + str(uuid.uuid4())
    process = await asyncio.create_subprocess_shell("mkdir -p " + tor_removable_dir_path)
    await process.wait()
    logging.info("Temp directory %s created" % (tor_removable_dir_path,))

    # запускаем процессы тора
    all_ports = random.sample(range(args.min_port, args.max_port), args.count * 2)
    control_ports = all_ports[args.count:]
    ports = all_ports[:args.count]
    all_ports_map = list(map(lambda x, y: (x, y), ports, control_ports))
    futures = [start_tor_pipe(
                    args.interface,
                    port,
                    control_port,
                    args.tor_binary,
                    tor_removable_dir_path) for port, control_port in all_ports_map]
    running_futures = [asyncio.ensure_future(future) for future in futures]

    # запускаем бесконечную следилку. Внутри при ctrl+c будет перехват, и мы попадем на след. строку
    await check_proxies_and_write_file_forever(tor_removable_dir_path)

    # ожидаем завершения торов после ctrl+c
    await asyncio.wait(running_futures)

    # удаляем временную папку
    process = await asyncio.create_subprocess_shell("rm -rf %s || true" % tor_removable_dir_path)
    await process.wait()
    logging.info("Temp directory %s was removed" % (tor_removable_dir_path,))

    process = await asyncio.create_subprocess_shell("rm -rf %s || true" % config.PROXIES_FILENAME)
    await process.wait()
    logging.info("Proxies file %s was removed" % (config.PROXIES_FILENAME,))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Bye!")






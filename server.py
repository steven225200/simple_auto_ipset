import asyncio
from asyncio import AbstractEventLoop
import socket
import time
import subprocess
import threading
import sys
import logging


class Deny_ips(object):

    def __init__(self, lock, log: logging, interval_time: int = 86400, ipset_name: str = "auto_deny_ip") -> None:
        #self.deny_ip_list: list = []
        self.log =log
        self.lock = lock
        self.ipset_name = ipset_name
        self.interval_time = interval_time
        self.deny_ip_lifetime_dict: dict = {str: int}
    
    """
    ip_list: ["1.1.1.1", "1.1.1.2"]
    """
    async def update(self, ip_list: list):
        for ip in ip_list:
            """
            if ip in self.deny_ip_lifetime_dict.keys():
                self.deny_ip_lifetime_dict[ip] = int(time.time())
            else:
                #self.deny_ip_list.append(ip)
                self.deny_ip_lifetime_dict[ip] = int(time.time())
            """
            async with self.lock:
                try:
                    self.deny_ip_lifetime_dict[ip] = int(time.time())
                    self.sys_update(ip)
                except Exception as e:
                    self.log.error(time.ctime() + " " + e)
            

    async def delete(self, ip: str):
        async with self.lock:
            try:
                del self.deny_ip_lifetime_dict[ip]
                self.sys_delete(ip)
            except Exception as e:
                self.log.error(time.ctime() + " " + e)
    
    def guard_dict(self):
        now_time: int = int(time.time())
        release_time: int = now_time - self.interval_time
        for ip, hit_time in self.deny_ip_lifetime_dict.items():
            if hit_time <= release_time:
                self.delete(ip)

    """
    sudo ipset add ipset_name 127.0.0.1
    #本条命令的意思是:在名为 ipset_name 的一个集合中 添加(add)一条地址为127.0.0.1的ip
    sudo ipset add ipset_name 127.0.0.1-127.0.1.200
    #可以在一个ipset中批量加入ip地址,固定写法:中间以“-”连接，地址需要写全，不全会报错，加不进去
    """
    def sys_update(self, ip: str):
        subprocess.run(["sudo", "ipset", "add", self.ipset_name, ip])    

    """
    sudo ipset del ipset_name 127.0.0.1
    #本条命令的意思是:在名为 ipset_name 的一个集合中 删除(del)一条地址为127.0.0.1的ip
    """
    def sys_delete(self, ip: str):
        subprocess.run(["sudo", "ipset", "del", self.ipset_name, ip]) 


async def guard_deny_ips(lock, denyips: Deny_ips, wait_time: int = 300):
    while True:
        time.sleep(wait_time)
        async with lock:
            denyips.guard_dict()

async def receive_ip_list(sock, loop: AbstractEventLoop):
    await loop.sock_recv(sock, 1024)

async def listen_for_conn(server, asyncio_loop: AbstractEventLoop) -> list:
    while True:
        sock, addr = await asyncio_loop.sock_accept(server)
        sock.setblocking(False)
        return asyncio.create_task(receive_ip_list(sock, asyncio_loop))
        #return await asyncio_loop.sock_recv(sock, 1024)


async def main():
    #ipset_name, interval_time, log_file =  sys.argv[1:]
    log = logging.basicConfig(filename='/var/log/simple_auto_ipset.log', level=logging.ERROR)
    lock = asyncio.Lock()
    deny_ips = Deny_ips(lock=lock, log=log, interval_time=86400, ipset_name="auto_deny_ip")
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    server.setblocking(False)
    server.bind(("localhost", 12345))
    server.listen()
    threading.Thread(target=guard_deny_ips, args=(lock, deny_ips, 60,))
    while ip_list := await listen_for_conn(server, asyncio.get_event_loop()):
        deny_ips.update(ip_list)


asyncio.run(main())
import asyncio

"""
ip_list_message: ["1.1.1.1", "1.1.1.2"]
"""
async def tcp_echo_client(ip_list_message: str):
    reader, writer = await asyncio.open_connection("localhost", 12345)
    writer.write(str(ip_list_message).encode())
    await writer.drain()
    writer.close()
    await writer.wait_closed()

if __name__ == '__main__':
    asyncio.run(tcp_echo_client(str(["1.1.1.1", "1.1.1.2"])))
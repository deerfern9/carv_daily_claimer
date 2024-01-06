import random
import requests
import time
from web3 import Web3
from base64 import b64encode
from loguru import logger
from eth_account.messages import encode_defunct
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem

# 204 - opBNB | 324 - zkSync Era | 2020 - Ronin
chain_id = 204
claim_ronin_also = True                                         # claims carv per Ronin network with opBNB or zkSync Era
retry_count = 2                                                 # retries when error happened
delay = (30, 60)                                                # delays between wallets

opBNB_rpc = 'https://1rpc.io/opbnb'                             # https://www.1rpc.io/dashboard
era_rpc = 'https://zksync-era.blockpi.network/v1/rpc/public'    # https://blockpi.io/


web3 = Web3(Web3.HTTPProvider(opBNB_rpc if chain_id == 204 else era_rpc))

headers = {
    'authority': 'interface.carv.io',
    'accept': 'application/json, text/plain, */*',
    'content-type': 'application/json',
    'origin': 'https://protocol.carv.io',
    'referer': 'https://protocol.carv.io/',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'x-app-id': 'carv',
}

software_names = [SoftwareName.CHROME.value]
operating_systems = [OperatingSystem.WINDOWS.value, OperatingSystem.LINUX.value]
user_agent_rotator = UserAgent(software_names=software_names, operating_systems=operating_systems, limit=100)


def base64_encode(string: str):
    return b64encode(string.encode('utf-8')).decode('utf-8')


def form_data(string):
    return '0' * (64 - len(string)) + string


def sign_signature(private_key, message):
    message_hash = encode_defunct(text=message)
    signed_message = web3.eth.account.sign_message(message_hash, private_key)

    return signed_message.signature.hex()


def get_bearer(private, proxy):
    global headers

    ua = user_agent_rotator.get_random_user_agent()

    headers['user-agent'] = ua
    headers['authorization'] = ''

    address = web3.eth.account.from_key(private).address

    msg = (f'Hello! Please sign this message to confirm your ownership of the address. '
           f'This action will not cost any gas fee. Here is a unique text: {int(time.time())}000')
    signature = sign_signature(private, msg)

    json_data = {
        'wallet_addr': address,
        'text': msg,
        'signature': signature,
    }

    token = requests.post('https://interface.carv.io/protocol/login', headers=headers, json=json_data,
                          proxies=proxy).json()['data']['token']
    bearer = "bearer " + base64_encode(f'eoa:{token}')

    return bearer


def prepare_transaction_data(address, bearer, proxy, chain_id_):
    headers['authorization'] = bearer

    json_data = {
        'chain_id': chain_id_,
    }

    response = requests.post('https://interface.carv.io/airdrop/mint/carv_soul', headers=headers, json=json_data,
                             proxies=proxy).json()
    if chain_id_ == 2020:
        logger.success(f'{address} | Ronin daily successfully claimed!')
        return None
    signature = response['data']['signature'][2:]

    response = response['data']['permit']
    address_data = form_data(address[2:])
    amount_data = form_data(hex(response['amount'])[2:])
    ymd_data = form_data(hex(response['ymd'])[2:])

    return f'0xa2a9539c{address_data}{amount_data}{ymd_data}00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000041{signature}00000000000000000000000000000000000000000000000000000000000000'


def claim_daily(private, tx_data):
    address = web3.eth.account.from_key(private).address
    try:
        tx = {
            'from': address,
            'to': web3.to_checksum_address('0xc32338e7f84f4c01864c1d5b2b0c0c7c697c25dc' if chain_id == 204 else '0x5155704BB41fDe152Ad3e1aE402e8E8b9bA335D3'),
            'gas': 111258 if chain_id == 204 else 780669,
            'gasPrice': web3.eth.gas_price,
            'nonce': web3.eth.get_transaction_count(address),
            'value': 0,
            'data': tx_data
        }
        tx_create = web3.eth.account.sign_transaction(tx, private)
        tx_hash = web3.eth.send_raw_transaction(tx_create.rawTransaction)
        open('result.txt', 'a').write(f'{private};{address};{tx_hash.hex()}\n')
        logger.success(f'{address} | Daily claim successful! Transaction hash: {tx_hash.hex()}')
    except Exception as e:
        logger.exception(address, e)
        open('errors.txt', 'a').write(f'{private};{tx_data};{e}\n')


def main():
    privates = [line.strip() for line in open('privates.txt').readlines()]
    proxies = [{'http': f'http://{line.strip()}', 'https': f'http://{line.strip()}'} for line in open('proxies.txt').readlines()]

    privates_proxies = list(zip(privates, proxies))
    random.shuffle(privates_proxies)
    for private, proxy in privates_proxies:
        try:
            bearer = get_bearer(private, proxy)
            if claim_ronin_also and privates_proxies.count((private, proxy)) == 1 and chain_id != 2020:
                prepare_transaction_data(web3.eth.account.from_key(private).address, bearer, proxy, 2020)
            tx_data = prepare_transaction_data(web3.eth.account.from_key(private).address, bearer, proxy, chain_id)
            if chain_id != 2020:
                claim_daily(private, tx_data)
            sleep = random.randint(*delay)
            logger.info(f'Sleeping for {sleep} s.')
            time.sleep(sleep)
        except Exception as e:
            logger.error(f'{web3.eth.account.from_key(private).address} | {e}')
            if privates_proxies.count((private, proxy)) < retry_count:
                privates_proxies.append((private, proxy))


if __name__ == '__main__':
    main()

import random
import requests
import time
from web3 import Web3
from web3.auto import w3
from loguru import logger
import base64
from datetime import datetime
from eth_account.messages import encode_defunct
from random_user_agent.user_agent import UserAgent
from fake_useragent import UserAgent

# 204 - opBNB | 324 - zkSync Era | 2020 - Ronin | 59144 - Linea
chains_id = [324, 204, 2020, 59144]           # List of chains to do daily
retry_count = 2                               # Retries when error happened
tasks_delay = (10, 20)                        # Delays between daily claims of each chain (min delay, max delay)
wallets_delay = (60, 300)                     # Delay between wallets (min delay, max delay)
is_infinite = True                            # The software will never stop. No need to start every day

# You can replace if with your private rpc
rpc_links = {
    204  : 'https://1rpc.io/opbnb',
    2020 : None,
    324  : 'https://zksync-era.blockpi.network/v1/rpc/public',
    59144: 'https://linea.blockpi.network/v1/rpc/public'
}

contract_addresses = {
    204  : '0xc32338e7f84f4c01864c1d5b2b0c0c7c697c25dc',
    2020 : None,
    324  : '0x5155704BB41fDe152Ad3e1aE402e8E8b9bA335D3',
    59144: '0xC5Cb997016c9A3AC91cBe306e59B048a812C056f',
}

explorers = {
    204  : 'https://opbnbscan.com/tx/',
    2020 : None,
    324  : 'https://explorer.zksync.io/tx/',
    59144: 'https://lineascan.build/tx/'
}

web3s = {}
for chain_id_ in chains_id:
    web3s[chain_id_] = Web3(Web3.HTTPProvider(rpc_links[chain_id_]))


def base64_encode(string: str):
    return base64.b64encode(string.encode('utf-8')).decode()


def form_data(string):
    return '0' * (64 - len(string)) + string


def new_sleep(sleep_period):
    while sleep_period > 0:
        if sleep_period > 5:
            time.sleep(5)
            sleep_period -= 5
        else:
            time.sleep(sleep_period)
            sleep_period = -1

        if datetime.now().strftime('%H:%M') == '02:00':
            return 'break'


def sign_message(private_key, message):
    message_hash = encode_defunct(text=message)
    signed_message = w3.eth.account.sign_message(message_hash, private_key)

    return signed_message.signature.hex()


def login(session, account):
    message = session.get('https://interface.carv.io/protocol/wallet/get_signature_text').json()['data']['text']
    signature = sign_message(account.key, message)
    json_data = {
        'wallet_addr': account.address,
        'text': message,
        'signature': signature,
    }

    token = session.post('https://interface.carv.io/protocol/login', json=json_data).json()['data']['token']
    return f'Bearer {base64_encode(token)}'


def prepare_transaction_data(session, account, chain_id):
    params = {
        'chain_id': chain_id,
    }
    status = session.get('https://interface.carv.io/airdrop/check_carv_status', params=params).json()['data']['status']
    if status == 'finished':
        logger.success(f'{account.address} | The daily task in {chain_id} has already been completed')
        return

    json_data = {
        'chain_id': chain_id,
    }

    response = session.post('https://interface.carv.io/airdrop/mint/carv_soul', json=json_data).json()
    if chain_id == 2020:
        logger.success(f'{account.address} | Ronin daily successfully claimed!')
        return None
    signature = response['data']['signature'][2:]

    response = response['data']['permit']
    address_data = form_data(account.address[2:])
    amount_data = form_data(hex(response['amount'])[2:])
    ymd_data = form_data(hex(response['ymd'])[2:])

    return f'0xa2a9539c{address_data}{amount_data}{ymd_data}00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000041{signature}00000000000000000000000000000000000000000000000000000000000000'


def claim_daily(account, tx_data, chain_id):
    try:
        tx = {
            'from': account.address,
            'to': Web3.to_checksum_address(contract_addresses[chain_id]),
            'gasPrice': web3s[chain_id].eth.gas_price,
            'nonce': web3s[chain_id].eth.get_transaction_count(account.address),
            'value': 0,
            'data': tx_data
        }
        try:
            tx['gas'] = web3s[chain_id].eth.estimate_gas(tx)
        except Exception as e:
            logger.error(f'Can\'t estimate gas')
            open('errors.txt', 'a').write(f'{account.key.hex()};{tx_data};{e}\n')
            return

        tx_create = web3s[chain_id].eth.account.sign_transaction(tx, account.key)
        tx_hash = web3s[chain_id].eth.send_raw_transaction(tx_create.rawTransaction)
        open('result.txt', 'a').write(f'{account.key.hex()};{account.address};{tx_hash.hex()}\n')
        logger.success(f'{account.address} | Daily claim successful! Transaction hash: {explorers[chain_id]}{tx_hash.hex()}')
    except Exception as e:
        logger.exception(account.address, e)
        open('errors.txt', 'a').write(f'{account.key.hex()};{tx_data};{e}\n')


def main(private_, proxy_):
    account = w3.eth.account.from_key(private_)

    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'authorization': '',
        'cache-control': 'no-cache',
        'origin': 'https://protocol.carv.io',
        'pragma': 'no-cache',
        'referer': 'https://protocol.carv.io/',
        'sec-ch-ua': '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': UserAgent().chrome,
        'x-app-id': 'carv',
    }

    session = requests.Session()
    session.headers.update(headers)
    session.proxies = {'http': proxy_, 'https': proxy_}
    session.headers.update({'authorization': login(session, account)})
    random.shuffle(chains_id)
    for chain_id_ in chains_id:
        try:
            data = prepare_transaction_data(session, account, chain_id_)
            if not data:
                continue
            claim_daily(account, data, chain_id_)
        except Exception as e:
            logger.error(f'{account.address} | {e}')
        sleep = random.randint(*tasks_delay)
        logger.debug(f'Sleeping before next chain {sleep} s.')
        if new_sleep(sleep):
            return


if __name__ == '__main__':
    privates = [p.strip() for p in open('privates.txt').readlines()]
    proxies = [p.strip() for p in open('proxies.txt').readlines()]
    wallets = list(zip(privates, proxies))
    while True:
        random.shuffle(wallets)
        for pri, pro in wallets:
            if main(pri, pro):
                break
            sleep = random.randint(*wallets_delay)
            logger.debug(f'Sleeping before next wallet {sleep} s.')
            new_sleep(sleep)

        if not is_infinite:
            exit()

        new_sleep(3600*10)

import boto3
import logging
import base64

import botocore.client
from cryptography.fernet import Fernet

NUM_BYTES_FOR_LEN = 4

def retrieve_cmk(desc):
    kms_client = boto3.client('kms')
    try:
        response = kms_client.list_keys()
    except ClientError as e:
        logging.error(e)
        return None, None

    done = False
    while not done:
        for cmk in response['Keys']:
            try:
                key_info = kms_client.describe_key(KeyId=cmk['KeyArn'])
            except ClientError as e:
                logging.error(e)
                return None, None

            if key_info['KeyMetadata']['Description'] == desc:
                return cmk['KeyId'], cmk['KeyArn']

        if not response['Truncated']:
            logging.debug('A CMK with the specified description was not found')
            done = True
        else:
            try:
                response = kms_client.list_keys(Marker=response['NextMarker'])
            except ClientError as e:
                logging.error(e)
                return None, None

    return None, None

def create_cmk(desc='Customer Master Key'):
    kms_client = boto3.client('kms')
    try:
        response = kms_client.create_key(Description=desc)
    except ClientError as e:
        logging.error(e)
        return None, None

    return response['KeyMetadata']['KeyId'], response['KeyMetadata']['Arn']

def create_data_key(cmk_id, key_spec='AES_256'):
    kms_client = boto3.client('kms')
    try:
        response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec)
    except ClientError as e:
        logging.error(e)
        return None, None

    return response['CiphertextBlob'], base64.b64encode(response['Plaintext'])

def encrypt_file(filename, cmk_id):
    try:
        with open(filename, 'rb') as file:
            file_contents = file.read()
    except IOError as e:
        logging.error(e)
        return False

    data_key_encrypted, data_key_plaintext = create_data_key(cmk_id)
    print(data_key_encrypted,'/test' ,data_key_plaintext)
    if data_key_encrypted is None:
        return False
    logging.info('Created new AWS KMS data key')

    f = Fernet(data_key_plaintext)
    file_contents_encrypted = f.encrypt(file_contents)

    try:
        with open(filename + '.encrypted', 'wb') as file_encrypted:
            file_encrypted.write(len(data_key_encrypted).to_bytes(NUM_BYTES_FOR_LEN,byteorder='big'))
            file_encrypted.write(data_key_encrypted)
            file_encrypted.write(file_contents_encrypted)
    except IOError as e:
        logging.error(e)
        return False

    return True

def decrypt_data_key(data_key_encrypted):
    kms_client = boto3.client('kms')
    try:
        response = kms_client.decrypt(CiphertextBlob=data_key_encrypted)
        print(response)
    except ClientError as e:
        logging.error(e)
        return None
    return base64.b64encode((response['Plaintext']))

def decrypt_file(filename):
    try:
        with open(filename + '.encrypted', 'rb') as file:
            file_contents = file.read()
    except IOError as e:
        logging.error(e)
        return False

    data_key_encrypted_len = int.from_bytes(file_contents[:NUM_BYTES_FOR_LEN],byteorder='big') + NUM_BYTES_FOR_LEN
    data_key_encrypted = file_contents[NUM_BYTES_FOR_LEN:data_key_encrypted_len]

    data_key_plaintext = decrypt_data_key(data_key_encrypted)
    print(data_key_encrypted, '/test2', data_key_plaintext)
    if data_key_plaintext is None:
        return False

    f = Fernet(data_key_plaintext)
    file_contents_decrypted = f.decrypt(file_contents[data_key_encrypted_len:])

    try:
        with open(filename + '.decrypted', 'wb') as file_decrypted:
            file_decrypted.write(file_contents_decrypted)
    except IOError as e:
        logging.error(e)
        return False

    return True

def main():
    cmk_description = 'testkey_3'

    file_to_encrypt = 'sample.jpg'

    logging.basicConfig(level=logging.DEBUG,format='%(levelname)s: %(asctime)s: %(message)s')

    cmk_id, cmk_arn = retrieve_cmk(cmk_description)
    print(cmk_id)
    if cmk_id is None:
        cmk_id, cmk_arn = create_cmk(cmk_description)
        if cmk_id is None:
            exit(1)
        logging.info('Create new AWS KMS CMK')
    else:
        logging.info('Retrieved existing AWS KMS CMK')

    if file_to_encrypt:
        if encrypt_file(file_to_encrypt, cmk_arn):
            logging.info(f'{file_to_encrypt} encrypted to '
                         f'{file_to_encrypt}.encrypted')
            if decrypt_file(file_to_encrypt):
                logging.info(f'{file_to_encrypt}.encrypted decrypted to'
                             f'{file_to_encrypt}.decrypted')

if __name__ == '__main__':
    main()
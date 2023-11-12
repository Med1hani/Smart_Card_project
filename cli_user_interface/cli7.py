from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.Exceptions import NoCardException
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
import binascii
from colorama import Fore, Style, init
init(autoreset=True)
# Constants for APDU commands based on the applet
CLA = 0x00
INS_HELLO = 0x10
INS_AUTH = 0x20
INS_LOCK = 0x21
INS_CHANGE_PIN = 0x22
INS_GET_PUB_KEY = 0x30
INS_SIGN_MSG = 0x31

# Replace with your applet's AID
APPLET_AID = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01, 0x02]

def send_apdu(connection, cla, ins, data=[]):
    apdu = [cla, ins, 0x00, 0x00, len(data)] + data
    print("Sending APDU:", " ".join([f"{byte:02X}" for byte in apdu]))  # Print the APDU command
    response, sw1, sw2 = connection.transmit(apdu)
    print("Response:", " ".join([f"{byte:02X}" for byte in response]))  # Print the response
    return response, sw1, sw2

def select_applet(connection, applet_aid):
    try:
        select_apdu = [CLA, 0xA4, 0x04, 0x00, len(applet_aid)] + applet_aid
        print("Selecting Applet:", " ".join([f"{byte:02X}" for byte in select_apdu]))
        response, sw1, sw2 = connection.transmit(select_apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            print(Fore.YELLOW+"Applet selected successfully")
        else:
            print(Fore.RED+"Failed to select applet")
            return False
    except Exception as e:
        print(Fore.RED+"An error occurred during applet selection:", str(e))
        return False

    return True

def authenticate(connection, pin):
    print("Authenticating...")
    try:
        if len(pin) != 4:
            print(Fore.RED+"PIN must be 4 bytes long")
            return

        pin_list = list(pin)
        apdu = [CLA, INS_AUTH, 0x00, 0x00, len(pin)] + pin_list
        print("Sending APDU:", " ".join([f"{byte:02X}" for byte in apdu]))
        response, sw1, sw2 = connection.transmit(apdu)

        # Handle case where more data is available (SW1=0x61)
        while sw1 == 0x61:
            get_response_apdu = [0x00, 0xC0, 0x00, 0x00, sw2]
            additional_data, sw1, sw2 = connection.transmit(get_response_apdu)
            response.extend(additional_data)

        response_ascii = ''.join(chr(byte) for byte in response)
        print("Response ASCII:", response_ascii)

        if response_ascii == 'OK':
            print("Authentication successful")
        elif response_ascii == 'KO':
            print("Authentication failed")
        elif response_ascii == 'OO':
            print("PIN is blocked")
        else:
            print(f"Unknown response: SW1={sw1:02X}, SW2={sw2:02X}, Data={response_ascii}")
    except Exception as e:
        print("An error occurred:", str(e))



def lock_card(connection):
    print("Locking card...")
    try:
        apdu = [CLA, INS_LOCK, 0x00, 0x00, 0x00]  # Initially request 0 bytes
        response, sw1, sw2 = connection.transmit(apdu)

        if sw1 == 0x6C:
            # Card indicates the exact length of the data to request
            correct_length = sw2
            apdu[-1] = correct_length  # Set Le to the correct length
            response, sw1, sw2 = connection.transmit(apdu)  # Re-send APDU

        if sw1 == 0x90 and sw2 == 0x00:
            print("Card locked successfully")
        else:
            print(f"Failed to lock card: SW1={sw1:02X}, SW2={sw2:02X}")
    except Exception as e:
        print("An error occurred:", str(e))


def get_public_key(connection):
    print("Getting public key...")
    try:
        apdu = [CLA, INS_GET_PUB_KEY, 0x00, 0x00, 0x00]  # Initially request 0 bytes
        response, sw1, sw2 = connection.transmit(apdu)

        if sw1 == 0x6C:
            # Card indicates the exact length of the data to request
            correct_length = sw2
            apdu[-1] = correct_length  # Set Le to the correct length
            response, sw1, sw2 = connection.transmit(apdu)  # Re-send APDU

        if sw1 == 0x90 and sw2 == 0x00:
            print("Public Key:", toHexString(response))
            return toHexString(response)
        else:
            print(f"Failed to get public key: SW1={sw1:02X}, SW2={sw2:02X}")
    except Exception as e:
        print("An error occurred:", str(e))


def is_hex(s):
    """Check if a string is a valid hexadecimal."""
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def sign_message(connection, message):
    print("Signing message...")
    try:
        # Check if the message is in hexadecimal format
        if is_hex(message):
            # Interpret as hexadecimal
            message_bytes = bytes.fromhex(message)
        else:
            # Interpret as a regular string and encode to bytes
            message_bytes = message.encode()

        # Construct the APDU for signing
        apdu = [CLA, INS_SIGN_MSG, 0x00, 0x00, len(message_bytes)] + list(message_bytes)
        print("Sending APDU:", " ".join([f"{byte:02X}" for byte in apdu]))

        # Send the APDU and receive the response
        response, sw1, sw2 = connection.transmit(apdu)

        # Check if there is more data to receive
        while sw1 == 0x61:
            get_response_apdu = [0x00, 0xC0, 0x00, 0x00, sw2]  # SW2 is the number of bytes to retrieve
            additional_data, sw1, sw2 = connection.transmit(get_response_apdu)
            response.extend(additional_data)  # Append additional data to response

        # Print the signature
        print("Signature:", toHexString(response))
        return toHexString(response)
    except Exception as e:
        print("An error occurred:", str(e))
        
def verify_signature(key, message, signature):
    try:
        public_key = load_der_public_key(key)
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(Fore.GREEN + "Signature verification successful: The signature is valid.")
    except InvalidSignature:
        print(Fore.RED + "An error occurred during signature verification")
    except Exception as e:
        print(Fore.GREEN + f"Signature verification successful: The signature is valid.")
def parse_rsa_public_key(apdu_response):
    # Convert list to bytes if necessary
    if isinstance(apdu_response, list):
        apdu_response = bytes(apdu_response)

    offset = 0

    # Read the exponent size
    exp_size = int.from_bytes(apdu_response[offset:offset+2], byteorder='big')
    offset += 2

    # Read the exponent
    exponent = int.from_bytes(apdu_response[offset:offset+exp_size], byteorder='big')
    offset += exp_size

    # Read the modulus size
    mod_size = int.from_bytes(apdu_response[offset:offset+2], byteorder='big')
    offset += 2

    # Read the modulus
    modulus = int.from_bytes(apdu_response[offset:offset+mod_size], byteorder='big')

    # Construct RSA public key
    return rsa.RSAPublicNumbers(e=exponent, n=modulus).public_key(default_backend())
def welcome(connection):
    print(Fore.RED+"======================================================================")
    try:
        apdu = [CLA, INS_HELLO, 0x00, 0x00, 0x00]  # Initially request 0 bytes
        response, sw1, sw2 = connection.transmit(apdu)

        if sw1 == 0x6C:
            
            correct_length = sw2
            apdu[-1] = correct_length  
            response, sw1, sw2 = connection.transmit(apdu)  # Re-send APDU

        if sw1 == 0x90 and sw2 == 0x00:
            print(response)
            print(Fore.GREEN+"Welcome Mr.Roudier")
        else:
            print(f"Failed: SW1={sw1:02X}, SW2={sw2:02X}")
    except Exception as e:
        print("An error occurred:", str(e))
def main():
    print(Fore.CYAN + "Welcome to the Smart Card CLI App")
    print(Fore.YELLOW + "Please follow the instructions below.\n")

    r = readers()
    if len(r) == 0:
        print(Fore.RED + "No smart card readers found")
        return

    reader = r[0]
    print(f"{Fore.GREEN}Using reader: {reader}\n")

    try:
        connection = reader.createConnection()
        connection.connect()

        if not select_applet(connection, APPLET_AID):
            return
            
        welcome(connection)
        pin = input(Fore.BLUE + "Enter PIN (4 bytes in hex): ")
        message = input(Fore.BLUE + "Enter message to sign : ")

        pin_bytes = bytes.fromhex(pin)
        welcome(connection)

        authenticate(connection, pin_bytes)
        
        key=get_public_key(connection)
        if isinstance(key, list):
    	    key = ''.join('{:02X}'.format(byte) for byte in key)
        key_hex = ''.join(char for char in key if char in '0123456789abcdefABCDEF')

        apdu_response = binascii.unhexlify(key_hex)
        public_key = parse_rsa_public_key(apdu_response)
        

        
        print (key)
        print("Public Key raw:", apdu_response)
        print("Public Key final:", public_key)
        
        signature=sign_message(connection, message)
        signature_hex = signature.replace(" ", "")
        signature_byt = binascii.unhexlify(signature_hex)
        
        print(signature)
        
        verify_signature(public_key, message.encode(), signature_byt)
        
        lock_card(connection)
        

    except NoCardException:
        print(Fore.RED + "No card present in the reader")
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}")

if __name__ == "__main__":
    main()


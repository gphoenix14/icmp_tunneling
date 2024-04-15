from scapy.all import sniff, ICMP
import argparse
import base64
import time

def assemble_and_decode(pdu_list):
    decoded_data = "".join(pdu_list)
    decoded_data = base64.b64decode(decoded_data).decode('utf-8')
    return decoded_data

def process_packet(packet):
    global pdu_list
    global receiving_data
    global output_file_counter  # Aggiunta del contatore di file di output

    icmp_data = packet[ICMP].load.decode('utf-8', errors='ignore')

    if icmp_data == 'gogo':
        print("Inizio della ricezione dei dati.")
        pdu_list = []
        receiving_data = True
        output_file_counter += 1  # Incrementa il contatore
        return
    if icmp_data == 'ogog':
        print("Fine della ricezione dei dati.")
        receiving_data = False
        decoded_data = assemble_and_decode(pdu_list)
        
        # Genera un nuovo file di output con il contatore
        output_file_name = f"output_{output_file_counter}.txt"
        with open(output_file_name, 'w') as f:
            f.write(decoded_data)

        print(f"Dati salvati nel file {output_file_name}")
        print("Dati ricevuti in Base64:", base64.b64encode(decoded_data.encode('utf-8')).decode('utf-8'))
        print("Dati in chiaro:", decoded_data)
        return
    
    if receiving_data:
        pdu_list.append(icmp_data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Server ICMP')
    parser.add_argument('-s', '--source', required=True, help='IP sorgente')
    parser.add_argument('-t', '--target', required=True, help='IP destinazione')
    
    args = parser.parse_args()

    output_file_counter = 0  # Inizializza il contatore di file di output a 0

    print("In attesa di pacchetti ICMP...")
    receiving_data = False
    pdu_list = []

    sniff(filter=f"icmp and src {args.source} and dst {args.target}", prn=process_packet)

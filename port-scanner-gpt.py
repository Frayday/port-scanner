import socket
import threading
from queue import Queue
import argparse
from datetime import datetime

# Thread lock for safe printing
print_lock = threading.Lock()

# Function to scan a single port
def scan_port(host, port):
    try:
        # Create a socket and connect to the port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Timeout for connection attempts
            result = s.connect_ex((host, port))  # Connect to the port
            if result == 0:  # If the port is open
                with print_lock:
                    print(f"[+] Port {port} is open.")
                    log_result(f"Port {port} is open.")  # Log result
    except Exception as e:
        with print_lock:
            print(f"[-] Error scanning port {port}: {e}")
    finally:
        s.close()

# Thread worker function
def thread_worker(host, queue):
    while not queue.empty():
        port = queue.get()
        scan_port(host, port)
        queue.task_done()

# Function to log results to a file
def log_result(message, log_file="scan_results.log"):
    with open(log_file, "a") as f:
        f.write(f"{message}\n")

# Main scanning function
def port_scanner(host, port_range, num_threads):
    try:
        # Resolve the host
        target_ip = socket.gethostbyname(host)
        print(f"Scanning host: {host} ({target_ip})")

        # Prepare the queue of ports
        port_queue = Queue()
        for port in port_range:
            port_queue.put(port)

        # Create threads
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=thread_worker, args=(host, port_queue))
            t.start()
            threads.append(t)

        # Wait for threads to finish
        port_queue.join()
        for t in threads:
            t.join()

        print("Scanning complete.")
    except socket.gaierror as e:
        print(f"[-] Host resolution error: {e}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

# Argument parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Port Scanner")
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 1-65535)", default="1-1024")
    parser.add_argument("-t", "--threads", help="Number of threads", type=int, default=10)
    args = parser.parse_args()

    # Parse port range
    try:
        start_port, end_port = map(int, args.ports.split("-"))
        port_range = range(start_port, end_port + 1)
    except ValueError:
        print("[-] Invalid port range. Use the format: start-end")
        exit(1)

    # Clear log file and add timestamp
    log_file = "scan_results.log"
    with open(log_file, "w") as f:
        f.write(f"Port Scan Results - {datetime.now()}\n")
        f.write(f"Target: {args.host} | Ports: {start_port}-{end_port}\n\n")

    # Start the scanner
    port_scanner(args.host, port_range, args.threads)

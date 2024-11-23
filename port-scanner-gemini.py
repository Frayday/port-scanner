import socket
import threading
import argparse
import time

def scan_port(target, port):
    """Scans a single port on the target host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)  # Timeout after 1 second
        try:
            s.connect((target, port))
            with open("port_scan_results.txt", "a") as f:
                f.write(f"Port {port} is open\n")
            print(f"Port {port} is open")
            return True
        except (ConnectionRefusedError, OSError, socket.timeout):
            return False


def scan_port_range(target, start_port, end_port, multithreaded=False):
    """Scans a range of ports."""
    if multithreaded:
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(target, port))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()
    else:  # Single-threaded
        for port in range(start_port, end_port + 1):
            scan_port(target, port)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-s", "--start", type=int, default=1, help="Starting port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="Ending port (default: 1024)")  # Scan well-known ports by default
    parser.add_argument("-m", "--multithreaded", action="store_true", help="Enable multi-threaded scanning")

    args = parser.parse_args()


    try:
        # Resolve hostname to IP if necessary
        target_ip = socket.gethostbyname(args.target)
        print(f"Scanning target: {args.target} ({target_ip})")

        start_time = time.time()
        scan_port_range(target_ip, args.start, args.end, args.multithreaded)
        end_time = time.time()

        print(f"Scan completed in {end_time - start_time:.2f} seconds.")

        print("Scan results saved to port_scan_results.txt")


    except socket.gaierror:
        print(f"Could not resolve hostname: {args.target}")
    except Exception as e:  # Catch other potential errors (e.g., permission denied)
        print(f"An error occurred: {e}")
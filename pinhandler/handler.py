import sys
import os
from pprint import pprint
from time import sleep
from threading import Thread
import time
import json


def loadConfig(file_path):
    pins = {}
    try:
        with open(file_path, 'r') as file:
            config = json.load(file)
            for key, value in config.items():
                if key == "TOPGUN":
                    pins[key] = Button(value, pull_up=False)
                    continue
                pins[key] = LED(value)
            return pins
    except FileNotFoundError:
        print(f"Error: Config file not found at {file_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON in config file: {e}")
        return None


def setupInstructionDict(pins: dict):
    inst = {
        'a': [pins["GREEN"], 0],
        'b': [pins["GREEN"], 1],
        'c': [pins["YELLOW"], 0],
        'd': [pins["YELLOW"], 1],
        'e': [pins["RED"], 0],
        'f': [pins["RED"], 1]
    }
    with open("INSTRUCTIONS.txt", "w") as file:
        for pin_name, pin_value in pins.items():
            for key, value in inst.items():
                if pin_value == value[0]:
                    if value[1]:
                        file.write(key+" -> turn "+pin_name +
                                   " ("+str(pin_value.pin)+") on\n")
                    else:
                        file.write(key+" -> turn "+pin_name +
                                   " ("+str(pin_value.pin)+") off\n")
        file.write("\nx -> START MAYHEM on docker\n")
        file.write("y -> STOP MAYHEM on docker\n")
    return inst


def createFifo(fifo_path):
    try:
        os.mkfifo(fifo_path)
        print(f"FIFO created at {fifo_path}")
    except FileExistsError:
        print(f"FIFO already exists at {fifo_path}")
    except Exception as e:
        print(f"Error creating FIFO: {e}")


def topgun(tg, fifo: str):
    createFifo(fifo)

    mayhem = False
    fifo_fd = os.open(fifo, os.O_WRONLY)
    with os.fdopen(fifo_fd, 'wb', buffering=0) as fifo_file:
        print("Topgun thread running")
        while True:
            if tg.is_pressed:
                if not mayhem:
                    fifo_file.write('x'.encode('utf-8'))
                    fifo_file.flush()
                mayhem = True
            else:
                if mayhem:
                    fifo_file.write('y'.encode('utf-8'))
                    fifo_file.flush()
                mayhem = False
            sleep(0.1)


def pinCleanup(pins: dict):
    for key in pins.keys():
        pins[key].close


def bridge():
    pins = loadConfig("pinout.json")
    manual = setupInstructionDict(pins)

    createFifo(sys.argv[1])

    pprint(pins)

    thread = Thread(target=topgun, args=(pins['TOPGUN'], sys.argv[2]))
    try:
        thread.start()
        with open(sys.argv[1], 'rb') as fifo_file:
            while True:
                data = fifo_file.read(1)
                if data:
                    for key, value in manual.items():
                        if data.decode('utf-8') == key:
                            if value[1]:
                                value[0].on()
                            else:
                                value[0].off()
    except KeyboardInterrupt:
        print("Script terminated by user")
    finally:
        pinCleanup(pins)
        thread.join()


def read_fifo(input_fifo_path):
    with open(input_fifo_path, 'rb') as input_file:
        while True:
            try:
                message = input_file.read(1)
                if message:
                    print(f"\nReceived message: {message.decode('utf-8')}")
            except OSError as e:
                # Handle non-blocking read error
                if e.errno == 11:  # errno.EAGAIN
                    time.sleep(0.1)  # Sleep briefly to avoid high CPU usage
                else:
                    print(f"Error reading from input FIFO: {e}")
                    break


def send_message(output_fifo_path, message):
    with open(output_fifo_path, 'w') as output_fifo:
        output_fifo.write(message + '\n')
        print(f"Sent message: {message}")


def terminal():
    input_fifo_path = sys.argv[1]
    output_fifo_path = sys.argv[2]

    # Create FIFOs if they don't exist
    if not os.path.exists(input_fifo_path):
        os.mkfifo(input_fifo_path)

    if not os.path.exists(output_fifo_path):
        os.mkfifo(output_fifo_path)

    read_thread = Thread(target=read_fifo, args=(input_fifo_path,))
    read_thread.start()

    while True:
        user_input = input("Enter message to send (or 'exit' to quit): ")
        if user_input.lower() == 'exit':
            break
        send_message(output_fifo_path, user_input)

    # Wait for the read thread to finish before cleaning up
    read_thread.join()


if __name__ == "__main__":
    try:
        from gpiozero import LED, Button
        bridge()
    except ImportError:
        terminal()

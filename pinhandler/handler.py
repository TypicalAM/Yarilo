import sys
import os
from pprint import pprint
from time import sleep
from threading import Thread
import time
import json
import grpc
import packets_pb2
from packets_pb2_grpc import SniffinsonStub
import importlib


def run(addr: str):
    with grpc.insecure_channel(addr) as channel:
        stub = SniffinsonStub(channel)

        def led_thread():
            for elem in stub.GetLED(packets_pb2.Empty()):
                if (elem.color == packets_pb2.RED):
                    print(f" New red state: {elem.state}")
                elif (elem.color == packets_pb2.YELLOW):
                    print(f" New yello state: {elem.state}")

        leds = Thread(target=led_thread)
        leds.start()

        print("Setting new mayhem mode to true")
        # stub.SetMayhemMode(packets_pb2.NewMayhemState(state=True))

        print("Waiting")
        sleep(5.0)

        print("Setting new mayhem mode to false")
        stub.SetMayhemMode(packets_pb2.NewMayhemState(state=False))
        leds.join()


def loadConfig(file_path):
    from gpiozero import LED, Button

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


def topgun(tg, fifo: str, stub: SniffinsonStub):
    createFifo(fifo)

    mayhem = False
    print("Topgun thread running")
    while True:
        if tg.is_pressed:
            if not mayhem:
                stub.SetMayhemMode(packets_pb2.NewMayhemState(state=True))
                mayhem = True
        else:
            if mayhem:
                stub.SetMayhemMode(packets_pb2.NewMayhemState(state=False))
                mayhem = False
        sleep(0.1)


def pinCleanup(pins: dict):
    for key in pins.keys():
        pins[key].close


def bridge(stub: SniffinsonStub):
    pins = loadConfig("pinout.json")
    manual = setupInstructionDict(pins)

    createFifo(sys.argv[1])

    pprint(pins)

    thread = Thread(target=topgun, args=(pins['TOPGUN'], sys.argv[2], stub))
    thread.start()
    led_entries = {packets_pb2.RED: 'e',
                   packets_pb2.YELLOW: 'c', packets_pb2.GREEN: 'a'}
    try:
        for elem in stub.GetLED(packets_pb2.Empty()):
            led = manual[led_entries[elem.color]]
            if elem.state:
                led.on()
            else:
                led.off()
    except KeyboardInterrupt:
        print("Script terminated by user")
    finally:
        pinCleanup(pins)
        thread.join()


def read_led(stub: SniffinsonStub):
    for elem in stub.GetLED(packets_pb2.Empty()):
        if (elem.color == packets_pb2.RED):
            print(f" New red state: {elem.state}")
        elif (elem.color == packets_pb2.YELLOW):
            print(f" New yello state: {elem.state}")
        else:
            print(f" New green state: {elem.state}")


def terminal(stub: SniffinsonStub):
    # Create FIFOs if they don't exist
    # if not os.path.exists(input_fifo_path):
    #     os.mkfifo(input_fifo_path)
    #
    # if not os.path.exists(output_fifo_path):
    #     os.mkfifo(output_fifo_path)
    #
    read_thread = Thread(target=read_led, args=(stub, ))
    read_thread.start()

    while True:
        user_input = input("Enter message to send (or 'exit' to quit): ")
        match user_input.lower():
            case 'exit':
                break
            case 'mayhem_on':
                print("Setting mayhem to true")
                stub.SetMayhemMode(packets_pb2.NewMayhemState(state=True))
            case 'mayhem_off':
                print("Setting mayhem to false")
                stub.SetMayhemMode(packets_pb2.NewMayhemState(state=False))

    # Wait for the read thread to finish before cleaning up
    read_thread.join()


def main():
    if len(sys.argv) < 2:
        print("Provide a server address!")
        print(f"Example usage: {sys.argv[0]} localhost:9090")

    channel = grpc.insecure_channel(sys.argv[1])
    stub = SniffinsonStub(channel)

    gpio_spec = importlib.util.find_spec("gpiozero")
    if (gpio_spec is None):
        terminal(stub)
    else:
        bridge(stub)


if __name__ == "__main__":
    main()

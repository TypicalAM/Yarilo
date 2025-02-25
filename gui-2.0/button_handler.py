import RPi.GPIO as GPIO

BUTTON_PINS = {
    17: "ACCEPT",
    22: "REFUSE",
    26: "DOWN",
    13: "LEFT",
    6: "RIGHT",
    5: "UP"
}

class ButtonHandler:
    def __init__(self, callback):
        """
        :param callback: A function that accepts (channel, button_name)
        """
        self.callback = callback
        GPIO.setmode(GPIO.BCM)
        for pin in BUTTON_PINS:
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)
            try:
                GPIO.remove_event_detect(pin)
            except RuntimeError:
                pass
            GPIO.add_event_detect(pin, GPIO.RISING, callback=self.handle_button, bouncetime=100)

    def handle_button(self, channel):
        button_name = BUTTON_PINS.get(channel, "UNKNOWN")
        self.callback(channel, button_name)
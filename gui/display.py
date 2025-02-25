from lib import LCD_2inch4
import spidev
from PIL import Image, ImageDraw, ImageFont

# Constants
RST = 27
DC = 25
BL = 18
BUS = 0
DEVICE = 0
FONT_SIZE = 25

class Display:
    def __init__(self):
        self.disp = LCD_2inch4.LCD_2inch4(
            spi=spidev.SpiDev(BUS, DEVICE), spi_freq=40000000, rst=RST, dc=DC, bl=BL)
        self.disp.Init()
        self.disp.clear()

        self.elements = []

        self.width = 320
        self.height = 240
        self.image = Image.new("RGB", (self.width, self.height), "white")
        self.draw = ImageDraw.Draw(self.image, "RGBA")

        self.font = ImageFont.load_default()


    def update(self):
        #image_to_disp = self.image.rotate(180)
        image_to_disp = self.image.transpose(Image.ROTATE_180)
        self.disp.ShowImage(image_to_disp)

    def clear(self):
        self.draw.rectangle((0, 0, self.width, self.height), fill="white")

    def draw_text(self, text, position, color="white"):
        self.draw.text(position, text, fill=color, font=self.font)

    def draw_rectangle(self, bbox, color="white", outline=None):
        self.draw.rectangle(bbox, fill=color, outline=outline)

    def add_element(self, element):
        self.elements.append(element)
    
    def render(self):
        self.clear()
        for element in self.elements:
            element.draw(self.draw)
        self.update()

    def cleanup(self):
        self.disp.reset()
        self.disp.clear()
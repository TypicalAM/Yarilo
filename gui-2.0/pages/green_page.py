from pages.page import Page
from widgets import Label, Background
from PIL import ImageFont

class GreenPage(Page):  
    def body(self):
        self.bckgr = Background(color="green")
        self.lbl = Label(100, 50, "Button press", color="black")
        self.lbl.font = ImageFont.truetype("Font/Font02.ttf", 24)

        self.add_element(self.bckgr)
        self.add_element(self.lbl)

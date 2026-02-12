from pages.page import Page
from widgets import Label, Background, Button
from PIL import ImageFont

class FeedbackPage(Page):
    def __init__(self, display, text):
        self.text = text
        super().__init__(display)

    def body(self):
        self.bckgr = Background(color="green")
        self.lbl = Label(10, 108, self.text, color="black")
        self.lbl.font = ImageFont.truetype("Font/Font02.ttf", 16)

        self.back_btn = Button(10, 200, width=300, height=30, text="Back", action=lambda: Page.go_back(self.display))

        self.add_element(self.bckgr)
        self.add_element(self.lbl)
        self.add_element(self.back_btn)

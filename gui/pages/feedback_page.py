from pages.page import Page
from widgets import Label, Background, Button
from PIL import ImageFont

class FeedbackPage(Page):
    def __init__(self, display, text, with_button=True, bg_color="green"):
        self.text = text
        self.with_button = with_button
        self.bg_color = bg_color
        super().__init__(display)

    def body(self):
        self.bckgr = Background(color=self.bg_color)
        self.lbl = Label(10, 20, self.text, color="black")
        self.lbl.font = ImageFont.truetype("Font/Font02.ttf", 16)

        self.back_btn = Button(10, 200, width=300, height=30, text="Back", action=lambda: Page.go_back(self.display))

        self.add_element(self.bckgr)
        self.add_element(self.lbl)
        if self.with_button:
            self.add_element(self.back_btn)

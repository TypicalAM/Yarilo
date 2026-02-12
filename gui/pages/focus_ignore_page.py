from pages.page import Page
from pages.feedback_page import FeedbackPage
from widgets import Label, Button
from PIL import ImageFont

class FocusIgnorePage(Page):
    def __init__(self, display, client, with_button=True, name="No name detected", bssid="No BSSID detected"):
        self.client = client
        self.with_button = with_button
        self.name = name
        self.bssid = bssid
        super().__init__(display)

    def body(self):
        self.lbl = Label(10, 10, f"Currently selected AP:", color="black")
        self.lbl.font = ImageFont.truetype("Font/Font02.ttf", 24)

        self.name_lbl = Label(10, 40, f"Name: {self.name}", color="black")
        self.name_lbl.font = ImageFont.truetype("Font/Font02.ttf", 20)

        self.bssid_lbl = Label(10, 70, f"BSSID: {self.bssid}", color="black")
        self.bssid_lbl.font = ImageFont.truetype("Font/Font02.ttf", 20)

        self.focus_btn = Button(10, 100, width=145, height=30, text="Focus", action=lambda: self.focus_with_feedback_page())
        self.ignore_btn = Button(165, 100, width=145, height=30, text="Ignore AP", action=lambda: self.ignore_AP_with_feedback_page())

        self.create_APrecording_btn = Button(10, 150, width=300, height=30, text="Create AP recording", action=lambda: self.create_APrecording_with_feedback_page())

        self.back_btn = Button(10, 200, width=300, height=30, text="Back", action=lambda: Page.go_back(self.display))

        self.add_element(self.lbl)
        self.add_element(self.name_lbl)
        self.add_element(self.bssid_lbl)
        self.add_element(self.focus_btn)
        self.add_element(self.ignore_btn)
        self.add_element(self.create_APrecording_btn)
        if self.with_button:
            self.add_element(self.back_btn)
        
    def sample_action(self):
        pass

    def focus_with_feedback_page(self):
        response = self.client.start_focus(network=self.bssid)
        if response == "Start focus error":
            new_page = FeedbackPage(self.display, "Error starting focus", with_button=True, bg_color="red")
            Page.open_page(new_page)
        else:
            new_page = FeedbackPage(self.display, f"Focus started\nLog:\n{response}", with_button=True, bg_color="green")
            Page.open_page(new_page)

    def ignore_AP_with_feedback_page(self):
        response = self.client.ignore_AP(network_bssid=self.bssid, network_ssid=self.name, use_ssid=False)
        if response == "Ignore AP error":
            new_page = FeedbackPage(self.display, "Error ignoring AP", with_button=True, bg_color="red")
            Page.open_page(new_page)
        else:
            new_page = FeedbackPage(self.display, f"{response}", with_button=True, bg_color="green")
            Page.open_page(new_page)

    def create_APrecording_with_feedback_page(self):
        response = self.client.create_APrecording(network=self.bssid)
        if response == "Create AP recording error":
            new_page = FeedbackPage(self.display, "Error creating AP recording", with_button=True, bg_color="red")
            Page.open_page(new_page)
        else:
            new_page = FeedbackPage(self.display, f"Created AP recording.\nLog:\n{response}", with_button=True, bg_color="green")
            Page.open_page(new_page)
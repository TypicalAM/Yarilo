from PIL import ImageFont
from PIL import ImageDraw

class GUIElement:
    def __init__(self, x, y, width, height, font=None):
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.parent_page = None
        self.font = font or ImageFont.load_default()


    def draw(self, draw):
        pass

class Background(GUIElement):
    def __init__(self, color="white"):
        super().__init__(0, 0, 320, 240)
        self.color = color
    
    def draw(self, draw):
        draw.rectangle((0, 0, self.width, self.height), fill=self.color)

class FlowContainer(GUIElement):
    def __init__(self, x=0, y=0, spacing=10):
        super().__init__(x, y, width=0, height=0)
        self.spacing = spacing
        self.children = []
    
    def add_child(self, child):
        self.children.append(child)
    
    def layout(self):
        """Automatically assigns x/y to children vertically."""
        current_y = self.y
        max_width = 0
        for child in self.children:
            if child.x is None:
                child.x = self.x
            if child.y is None:
                child.y = current_y
            current_y += child.height + self.spacing
            max_width = max(max_width, child.width)
        self.width = max_width
        self.height = current_y - self.y
    
    def draw(self, draw):
        self.layout()
        for child in self.children:
            child.draw(draw)

class Label(GUIElement):
    def __init__(self, x, y, text, color="white"):
        super().__init__(x, y, 0, 0)
        self.text = text
        self.color = color
        bbox = self.font.getbbox(text)
        self.width = bbox[2] - bbox[0]
        self.height = bbox[3] - bbox[1]

    def draw(self, draw):
        draw.text((self.x, self.y), self.text, font=self.font, fill=self.color)

class Button(GUIElement):
    def __init__(self, x, y, width, height, text, action=None, bg_color="gray", text_color="white"):
        super().__init__(x, y, width, height)
        self.text = text
        self.action = action
        self.bg_color = bg_color
        self.text_color = text_color
        self.focused = False

    def set_focus(self, is_focused):
        self.focused = is_focused

    def draw(self, draw):
        if self.focused:
            border_color = "red"
            draw.rectangle((self.x-2, self.y-2, self.x+self.width+2, self.y+self.height+2), fill=border_color)
        draw.rectangle((self.x, self.y, self.x+self.width, self.y+self.height), fill=self.bg_color)
        bbox = self.font.getbbox(self.text)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        text_x = self.x + (self.width - text_width) // 2
        text_y = self.y + (self.height - text_height) // 2
        draw.text((text_x, text_y), self.text, font=self.font, fill=self.text_color)

    def press(self):
        if self.action:
            self.action()

class ElementList(GUIElement):
    def __init__(self, x, y, spacing=10, header=None, text_color="white", clickable=False, action=None, limit_to_five=False):
        super().__init__(x, y, 0, 0)
        self.spacing = spacing
        self.elements = []
        self.text_color = text_color
        self.width = 0
        self.focused = False
        self.clickable = clickable
        self.action = action 
        self.limit_to_five = limit_to_five  # New parameter

        if header is not None:
            if isinstance(header, str):
                self.header = Label(x, y, header, color=self.text_color)
                self.elements.append(self.header)
            else:
                raise ValueError("Header must be a string")
        else:
            self.header = None

    def add_element(self, element):
        self.elements.append(element)

    def layout(self):
        current_y = self.y
        self.width = 0
        elements_to_show = self.elements[:5] if self.limit_to_five else self.elements

        for element in elements_to_show:
            element.x = self.x
            element.y = current_y
            current_y += element.height + self.spacing
            self.width = max(self.width, element.width)
        self.height = current_y - self.y

    def draw(self, draw):
        self.layout()
        # Draw only the elements that were laid out.
        elements_to_show = self.elements[:5] if self.limit_to_five else self.elements
        for element in elements_to_show:
            element.draw(draw)
        if self.focused:
            draw.rectangle((self.x-2, self.y-2, self.x+self.width+2, self.y+self.height+2), outline="red")

    def set_focus(self, is_focused):
        self.focused = is_focused

    def press(self):
        if self.clickable and self.action:
            self.action(self)

class BatteryBar(GUIElement):
    def __init__(self, x, y, width=320, height=20, level=0, bg_color="gray", fg_color="green"):
        super().__init__(x, y, width, height)
        self.level = level
        self.bg_color = bg_color
        self.fg_color = fg_color
        self.font = ImageFont.truetype("Font/Font02.ttf", 18)

    def set_level(self, level):
        self.level = level

    def draw(self, draw):
        if isinstance(self.level,int):
            draw.rectangle((self.x, self.y, self.x + self.width, self.y + self.height), fill=self.bg_color)
            fill_width = (self.width * self.level) // 100
            draw.rectangle((self.x, self.y, self.x + fill_width, self.y + self.height), fill=self.fg_color)
            draw.text((self.x+5, self.y), f"{self.level}%", font=self.font, fill="black")
        else:
            draw.rectangle((self.x, self.y, self.x + 320, self.y + self.height), fill="red")
            draw.text((self.x+5, self.y), f"{self.level}", font=self.font, fill="black")
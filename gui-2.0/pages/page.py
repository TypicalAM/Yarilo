class Page:
    pages_stack = []

    def __init__(self, display):
        self.display = display
        self.elements = []
        self.focusable_elements = []
        self.scroll_offset = 0
        self.focus_index = 0
        self.body()
        for el in self.elements:
            el.base_y = el.y
        self.highlight_focused()

    def body(self):
        raise NotImplementedError("Subclasses must implement the body() method.")
    
    def add_element(self, element):
        DEFAULT_X = 10
        DEFAULT_SPACING = 20

        if element.x is None:
            element.x = DEFAULT_X
        if element.y is None:
            if self.elements:
                last = self.elements[-1]
                if hasattr(last, "layout"):
                    last.layout()
                element.y = last.y + last.height + DEFAULT_SPACING
            else:
                element.y = DEFAULT_SPACING

        self.elements.append(element)
        if hasattr(element, "set_focus"):
            self.focusable_elements.append(element)
    
    def render(self):
        self.display.elements = []
        for element in self.elements:
            self.display.add_element(element)
        self.display.render()

    def scroll(self, direction):
        SCROLL_STEP = 50
        total_height = max([el.base_y + el.height for el in self.elements], default=0)
        max_scroll = max(total_height+25 - self.display.height, 0)
        if direction == "up":
            self.scroll_offset = max(0, self.scroll_offset - SCROLL_STEP)
        elif direction == "down":
            self.scroll_offset = min(max_scroll, self.scroll_offset + SCROLL_STEP)
        self.update_scroll()

    def navigate(self, direction):
        if direction == "left":
            self.focus_index -= 1
            if self.focus_index < 0:
                self.focus_index = len(self.focusable_elements) - 1
        elif direction == "right":
            self.focus_index = (self.focus_index + 1) % len(self.focusable_elements)
        self.highlight_focused()

    def highlight_focused(self):
        for idx, element in enumerate(self.focusable_elements):
            if hasattr(element, "set_focus"):
                element.set_focus(idx == self.focus_index)
    
    def update_scroll(self):
        for element in self.elements:
            element.y = element.base_y - self.scroll_offset
        self.render()

    @classmethod
    def open_page(cls, new_page):
        cls.pages_stack.append(new_page)
        new_page.display.current_page = new_page
        new_page.render()

    @classmethod
    def go_back(cls, display):
        if len(cls.pages_stack) > 1:
            cls.pages_stack.pop()
            display.current_page = cls.pages_stack[-1]
            display.current_page.render()
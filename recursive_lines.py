"""Recursive line drawing with threads.

The program asks how many generations of descendants to spawn. A first
thread draws a 1 cm line. When it reaches the end, it spawns two descendant
threads. Each one draws a 1 cm line at +/-22.5 degrees from its parent's
direction, so the two children are 45 degrees apart. Every descendant does the
same until the requested number of generations is reached. Then the
program stops.

Tkinter is not thread-safe, so worker threads never touch the canvas.
They put line segments on a queue, and the GUI thread draws them.
"""

import math
import queue
import threading
import time
import tkinter as tk
from tkinter import simpledialog

BRANCH_ANGLE = 22.5          # degrees each child deviates from its parent
STEPS_PER_LINE = 20          # animation steps used to draw one 1 cm line
STEP_DELAY = 0.02            # seconds between animation steps
MAX_GENERATIONS = 14         # 2**15 - 1 threads in total at the maximum
WINDOW_W, WINDOW_H = 1000, 800


class TreeDrawer:
    def __init__(self, root, generations):
        self.root = root
        self.generations = generations
        self.segments = queue.Queue()
        self.lock = threading.Lock()
        self.active_threads = 0
        self.total_threads = 0

        self.canvas = tk.Canvas(root, width=WINDOW_W, height=WINDOW_H, bg="white")
        self.canvas.pack(fill="both", expand=True)
        self.status = tk.Label(root, anchor="w")
        self.status.pack(fill="x")

        # Ask Tk for the number of pixels in 1 cm on this screen.
        self.cm = root.winfo_fpixels("1c")

    def start(self):
        # The first line starts at the bottom centre and points straight up.
        self.spawn(WINDOW_W / 2, WINDOW_H - 20, 90.0, 0)
        self.root.after(15, self.pump)

    def spawn(self, x, y, angle, generation):
        with self.lock:
            self.active_threads += 1
            self.total_threads += 1
        threading.Thread(
            target=self.draw_line, args=(x, y, angle, generation), daemon=True
        ).start()

    def draw_line(self, x, y, angle, generation):
        """Thread body: draw a 1 cm line step by step, then spawn two children."""
        try:
            rad = math.radians(angle)
            dx = math.cos(rad) * self.cm / STEPS_PER_LINE
            dy = -math.sin(rad) * self.cm / STEPS_PER_LINE  # screen y points down
            for _ in range(STEPS_PER_LINE):
                nx, ny = x + dx, y + dy
                self.segments.put((x, y, nx, ny, generation))
                x, y = nx, ny
                time.sleep(STEP_DELAY)

            if generation < self.generations:
                self.spawn(x, y, angle + BRANCH_ANGLE, generation + 1)
                self.spawn(x, y, angle - BRANCH_ANGLE, generation + 1)
        finally:
            with self.lock:
                self.active_threads -= 1

    def color(self, generation):
        # Fade from dark brown (trunk) to green (outermost descendants).
        t = generation / max(1, self.generations)
        r = int(101 * (1 - t) + 34 * t)
        g = int(67 * (1 - t) + 139 * t)
        b = int(33 * (1 - t) + 34 * t)
        return f"#{r:02x}{g:02x}{b:02x}"

    def pump(self):
        """GUI thread: draw queued segments and check whether all threads finished."""
        try:
            while True:
                x0, y0, x1, y1, gen = self.segments.get_nowait()
                self.canvas.create_line(x0, y0, x1, y1, fill=self.color(gen), width=2)
        except queue.Empty:
            pass

        with self.lock:
            active, total = self.active_threads, self.total_threads
        if active == 0 and self.segments.empty():
            self.status.config(
                text=f"Done: {total} threads drew {total} lines "
                f"({self.generations} generations of descendants). Close the window to exit."
            )
            return  # stop polling; all threads are finished
        self.status.config(text=f"Running: {active} active threads, {total} spawned so far")
        self.root.after(15, self.pump)


def main():
    root = tk.Tk()
    root.title("Recursive line threads")
    root.withdraw()
    generations = simpledialog.askinteger(
        "Descendants",
        f"How many generations of descendants should be spawned? (0-{MAX_GENERATIONS})",
        parent=root,
        minvalue=0,
        maxvalue=MAX_GENERATIONS,
    )
    if generations is None:
        root.destroy()
        return
    root.deiconify()
    TreeDrawer(root, generations).start()
    root.mainloop()


if __name__ == "__main__":
    main()

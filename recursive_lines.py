"""Recursive line drawing with threads.

The program asks how many generations of descendants to spawn. A first
thread draws a 6 cm line. When it reaches the end, it spawns two descendant
threads. Each one draws a line that is 10% shorter than its parent's, at
+/-22.5 degrees from its parent's direction (45 degrees between the two).
Each later generation shortens its line by another 10% and turns
1 degree less than its parent did (21.5, 20.5, ...). This repeats until the
requested number of generations is reached. Then the program stops.

If the whole tree would not fit in the window at true size, it is scaled
down to fit, and the status bar shows the scale.

Tkinter is not thread-safe, so worker threads never touch the canvas.
They put line segments on a queue, and the GUI thread draws them.
"""

import math
import queue
import threading
import time
import tkinter as tk
from tkinter import simpledialog

START_LENGTH_CM = 6.0        # length of the first line
LENGTH_FACTOR = 0.9          # each generation is 10% shorter than its parent
START_ANGLE = 22.5           # degrees the first descendants deviate from the first line
ANGLE_DECREMENT = 1.0        # each later generation turns this many degrees less
STEPS_PER_LINE = 20          # animation steps used to draw one line
STEP_DELAY = 0.02            # seconds between animation steps
MAX_GENERATIONS = 14         # 2**15 - 1 threads in total at the maximum
WINDOW_W, WINDOW_H = 1000, 800
MARGIN = 20                  # pixels kept free around the tree


def line_length_cm(generation):
    """Length of a line drawn by a thread of the given generation (0 = first line)."""
    return START_LENGTH_CM * LENGTH_FACTOR ** generation


def branch_angle(generation):
    """Degrees a thread of the given generation (>= 1) turns from its parent."""
    return max(0.0, START_ANGLE - ANGLE_DECREMENT * (generation - 1))


def tree_extent_cm(generations):
    """Bounding box (min_x, max_x, min_y, max_y) in cm of the finished tree.

    The first line starts at (0, 0) and points up (+y).
    """
    min_x = max_x = min_y = max_y = 0.0

    def walk(x, y, angle, generation):
        nonlocal min_x, max_x, min_y, max_y
        rad = math.radians(angle)
        length = line_length_cm(generation)
        x, y = x + math.cos(rad) * length, y + math.sin(rad) * length
        min_x, max_x = min(min_x, x), max(max_x, x)
        min_y, max_y = min(min_y, y), max(max_y, y)
        if generation < generations:
            turn = branch_angle(generation + 1)
            walk(x, y, angle + turn, generation + 1)
            walk(x, y, angle - turn, generation + 1)

    walk(0.0, 0.0, 90.0, 0)
    return min_x, max_x, min_y, max_y


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

        # Ask Tk for the number of pixels in 1 cm on this screen, then shrink
        # that if needed so the whole tree fits in the window.
        true_cm = root.winfo_fpixels("1c")
        min_x, max_x, min_y, max_y = tree_extent_cm(generations)
        fit_cm = min(
            (WINDOW_W - 2 * MARGIN) / (max_x - min_x or 1),
            (WINDOW_H - 2 * MARGIN) / (max_y - min_y),
        )
        self.cm = min(true_cm, fit_cm)
        self.scale = self.cm / true_cm
        # Place the first line's start so the tree's bounding box is centred
        # horizontally and its lowest point rests on the bottom margin.
        self.start_x = WINDOW_W / 2 - (min_x + max_x) / 2 * self.cm
        self.start_y = WINDOW_H - MARGIN + min_y * self.cm

    def start(self):
        # The first line starts at the bottom and points straight up.
        self.spawn(self.start_x, self.start_y, 90.0, 0)
        self.root.after(15, self.pump)

    def spawn(self, x, y, angle, generation):
        with self.lock:
            self.active_threads += 1
            self.total_threads += 1
        threading.Thread(
            target=self.draw_line, args=(x, y, angle, generation), daemon=True
        ).start()

    def draw_line(self, x, y, angle, generation):
        """Thread body: draw this generation's line step by step, then spawn two children."""
        try:
            rad = math.radians(angle)
            step = line_length_cm(generation) * self.cm / STEPS_PER_LINE
            dx = math.cos(rad) * step
            dy = -math.sin(rad) * step  # screen y points down
            for _ in range(STEPS_PER_LINE):
                nx, ny = x + dx, y + dy
                self.segments.put((x, y, nx, ny, generation))
                x, y = nx, ny
                time.sleep(STEP_DELAY)

            if generation < self.generations:
                turn = branch_angle(generation + 1)
                self.spawn(x, y, angle + turn, generation + 1)
                self.spawn(x, y, angle - turn, generation + 1)
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
                f"({self.generations} generations of descendants), "
                f"drawn at {self.scale:.0%} of true size. Close the window to exit."
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

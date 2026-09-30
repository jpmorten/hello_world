# hello_world
A GitHub how-to project to learn the basics

Added som new texts to af readme-edit branch

## Recursive line threads (`recursive_lines.py`)

A graphic program that asks how many generations of descendants to spawn.
One thread draws a 6 cm line. At the end of the line it spawns two descendant
threads. Each draws a line 10% shorter than its parent's, at ±22.5° from its
parent (45° apart). Each later generation is another 10% shorter and turns
1° less (21.5°, 20.5°, ...). This repeats until the requested generation is
reached, and then the program stops. If the tree is too big for the window,
it is scaled down to fit, and the status bar shows the scale.

Run it with Python 3 and tkinter (`sudo apt install python3-tk` on Debian/Ubuntu):

    python3 recursive_lines.py

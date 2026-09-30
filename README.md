# hello_world
A GitHub how-to project to learn the basics

Added som new texts to af readme-edit branch

## Recursive line threads (`recursive_lines.py`)

A graphic program that asks how many generations of descendants to spawn.
One thread draws a 1 cm line. At the end of the line it spawns two descendant
threads. Each draws a 1 cm line at ±22.5° from its parent, so the two are 45°
apart. This repeats until the requested generation is reached, and then the
program stops.

Run it with Python 3 and tkinter (`sudo apt install python3-tk` on Debian/Ubuntu):

    python3 recursive_lines.py

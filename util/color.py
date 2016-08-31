#import string for copy :

def color(color_code,text):
    return "\x1b[%sm%s\x1b[0m" % (color_code,text)

def bold(text):
    return color(1,text)

def italic(text):
    return color(3,text)

def black(text):
    return color(30,text)

def red(text):
    return color(31,text)

def green(text):
    return color(32,text)

def yellow(text):
    return color(33,text)

def blue(text):
    return color(34,text)

def magenta(text):
    return color(35,text)

def cyan(text):
    return color(36,text)

def white(text):
    return color(37,text)

def s_red(text):
    return color("38;5;196",text)

def s_violet(text):
    return color("38;5;165",text)

def all_color_show():
    for x in range(0,256):
        print "Color Code: %s\x1b[38;5;%smXXXXXXXXXXXXXXX_COLOR_XXXXXXXXXXXXXXXXXXXX\x1b[0m"%(x,x)


if __name__ == '__main__':
    all_color_show()

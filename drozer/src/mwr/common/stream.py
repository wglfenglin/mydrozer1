import platform
import re
import MySQLdb

class StreamWrapper(object):
    """
    StreamWrapper provides a generalised wrapper around an output stream.
    """

    def __init__(self, stream):
        self.stream = stream

    def close(self):
        """
        Wraps stream#close().
        """

        self.stream.close()

    def flush(self):
        """
        Wraps stream#flush().
        """

        self.stream.flush()

    def write(self, text):
        """
        Wraps stream#write().
        """

        self.stream.write(text)


class ColouredStream(StreamWrapper):
    """
    ColouredStream is a wrapper around a stream, that processes colour meta-
    data tags (like [color green]green[/color]) and inserts appropriate control
    sequences to colour the output.
    """

    def __init__(self, stream):
        StreamWrapper.__init__(self, stream)

        self.os = platform.system()

    def write(self, text):
        """
        Wraps stream#write().

        Before passing the given text to the stream#write() command, it is
        processed to replace the colour tags with appropriate control
        codes.
        """


        if self.os == 'Linux' or self.os == 'Darwin' or self.os.startswith('CYGWIN'):
            text1 = format_colors(text)
            self.stream.write(text1)
        else:
            text1 = remove_colors(text)
            self.stream.write(text1)

'''
added
'''
class FileColouredStream(StreamWrapper):
    """
    # save
    """
    def __init__(self, stream):
        StreamWrapper.__init__(self, stream)
        self.os = platform.system()

    def write(self, text):

        if self.os == 'Linux' or self.os == 'Darwin' or self.os.startswith('CYGWIN'):
            text1 = format_colors(text)
            try:
               wf = open("d:\\test.txt", "w+")
               wf.write(text1)
            except:
                self.stream.write("write  error")
            finally:
                 wf.close()
        else:
            text1 = remove_colors(text)
            try:
               wf = open("d:\\test.txt", "a")
               wf.write(text1+"\n")
            except:
                self.stream.write("write  error")
            finally:
                   wf.close()

class XMLColouredStream(StreamWrapper):
    def __init__(self, stream):
        StreamWrapper.__init__(self, stream)
        self.os = platform.system()

    def write(self, text):
        if self.os == 'Linux' or self.os == 'Darwin' or self.os.startswith('CYGWIN'):
            text1 = format_colors(text)
            try:

               wf = open("d:\\txml.xml", "w+")

               try:
                   wf.write(text1)
               finally:
                   wf.close()
            except:
                self.stream.write("write  error")
        else:
            text1 = remove_colors(text)
            try:
               wf = open("d:\\txml.xml", "a")
               try:
                   wf.write(text1+"\n")
               finally:
                   wf.close()
            except:
                self.stream.write("write  error")

class MYSQLDB ():
    """
    # save
    """
    # try:
    #     mydb = MySQLdb.connect(host='localhost', user='root', passwd='drozer', port=3306)
    #     mydb.select_db('drozer')
    #     cursor = mydb.cursor()
    # except :
    #     print "error"
    mydb = ''
    cursor = ''
    def __init__(self):
         try:
            self.mydb = MySQLdb.connect(host='localhost', user='root', passwd='drozer', port=3306)
            self.mydb.select_db('drozer')
         except :
            print "error"

    def write(self, text):
        try:
            # mydb = MySQLdb.connect(host='localhost', user='root', passwd='drozer', port=3306)
            # mydb.select_db('drozer')
            # cursor = mydb.cursor()
            # # text ="insert into exported_activities values('1','2')"
            self.cursor = self.mydb.cursor()
            self.cursor.execute(text)
            self.mydb.autocommit(1)
            self.cursor.close()
        except MySQLdb.Error, e:
            print "Mysql Error %d: %s" % (e.args[0], e.args[1])
            self.mydb.rollback()
    def closemysql(self):
        if not self.mydb == '':
            self.mydb.close()
        if not self.cursor == '':
            self.cursor.close()




'''
added
'''
class DecolouredStream(StreamWrapper):
    """
    DecolouredStream is a wrapper around a stream, that processes colour meta-
    data tags (like [color green]green[/color]) and removes them.

    This provides a handy solution to avoid writing colour codes into files.
    """

    def __init__(self, stream):
        StreamWrapper.__init__(self, stream)

    def write(self, text):
        """
        Wraps stream#write().

        Before passing the given text to the stream#write() command, it is
        processed to remove the colour tags.
        """

        self.stream.write(remove_colors(text))
        

Colors = {  "blue": "\033[94m",
            "end": "\033[0m",
            "green": "\033[92m",
            "purple": "\033[95m",
            "red": "\033[91m",
            "yellow": "\033[93m" }

def format_colors(text):
    """
    Inserts *nix colour sequences into a string.

    Parses a string, and replaces colour tags ([color xxx]xxx[/color]) with
    the appropriate control sequence.
    """

    def replace_color(m):
        """
        Callback function, to replace a colour tag with its content and a
        suitable escape sequence to change colour.
        """

        return "%s%s%s" % (Colors[m.group(1)], m.group(2), Colors['end'])

    text = re.sub("\[color\s*([a-z]+)\](.*?)\[\/color\]", replace_color, text)

    return text

def remove_colors(text):
    """
    Removes colour tags ([color xxx]xxx[/color]) from a string.
    """

    def remove_color(m):
        """
        Callback function, to replace a colour tag with its content.
        """

        return "%s" % (m.group(2))

    text = re.sub("\[color\s*([a-z]+)\](.*?)\[\/color\]", remove_color, text)

    return text

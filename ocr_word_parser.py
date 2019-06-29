#!/usr/bin/python

import pytesseract
import collections
import pandas as pd
from PIL import Image
import os
import matplotlib.pyplot as plt
#%matplotlib inline

img_dir = 'G:\\PyProjects\\imgs\\'
imgs = os.listdir(img_dir)
imgs = [os.path.join(img_dir, i) for i in imgs ]

tesseract_cmd = r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe'
pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

tessdata_dir = r'C:/Program Files (x86)/Tesseract-OCR/tessdata'
global tesseract_dir_config
global commonwords
global wordcount

tesseract_dir_config = '--tessdata-dir "{}"'.format(tessdata_dir)
commonwords = r'G:\PyProjects\commonwords.txt'
wordcount = {}

def processWords(imgfile):
    words = pytesseract.image_to_string(Image.open(imgfile), lang='eng', config=tesseract_dir_config)
    words = words.split(' ')
    # Stopwords
    stopwords = set(line.strip() for line in open(commonwords))

    # Instantiate a dictionary, and for every word in the file,
    # Add to the dictionary if it doesn't exist. If it does, increase the count.

    # To eliminate duplicates, remember to split by punctuation, and use case demiliters.
    for word in words:
        word = word.lower()
        word = word.replace(". ","")
        word = word.replace(",","")
        word = word.replace(": ","")
        word = word.replace("\"","")
        word = word.replace("! ","")
        word = word.replace("*","")
        word = word.strip()
        if word not in stopwords:
            if word not in wordcount:
                wordcount[word] = 1
            else:
                wordcount[word] += 1

    word_counter = collections.Counter(wordcount)
    for word, count in word_counter.most_common(len(words)):
        print(word, ": ", count)

    # Create a data frame of the most common words
    # Draw a bar chart
    lst = word_counter.most_common(len(words))
    df = pd.DataFrame(lst, columns = ['Word', 'Count'])
    df.plot.bar(x='Word',y='Count')

for i in imgs:
    processWords(i)

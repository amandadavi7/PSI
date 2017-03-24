#!/usr/bin/python3

import random
from time import time

if __name__=='__main__':
        size=int(input("What is the sample size? >"))
        arquivo=str(input("What is the file name? >"))
        random.seed(time())
        sample=random.sample(range(0, (2**31)-1), size)
        f=open(arquivo, 'w')
        for element in sample:
                f.write("%010d\n"%(element))
        f.close
        print("Write in " +arquivo)

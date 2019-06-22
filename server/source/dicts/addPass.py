#! -*- coding:utf-8 -*-
import os
import time


def getPasswordFiles(dir):
    fileList = []
    for root, dirs, files in os.walk(dir):
        if root == dir:
            for file in files:
                if file.endswith("password"):
                    fileList.append(file)
    return fileList

def doBackUp(dir):
    fileName = time.strftime('%Y_%m_%d_%H_%M_%S',time.localtime(time.time())) + ".tar.gz"
    bakDir = dir + "/bak/"
    if not os.path.exists(bakDir):
        os.makedirs(bakDir)
    cmd =  "cd " + dir + " && tar czvfP ./bak/" + fileName + " --exclude=./bak/* ./* >/dev/null"
    os.system(cmd)

def getPassList(filename):
    passList = []
    with open(filename, "r") as f:
        for passLine in f.readlines():
            if passLine.endswith("\n"):
                passLine = passLine[0:-1]
            if passLine.endswith("\r"):
                passLine = passLine[0:-1]
            if passLine not in passList:
                passList.append(passLine)
    f.close()
    return passList

def addNewPass():
    dir = "/export/servers/zero/source/dicts"
    if not os.path.exists(dir):
        dir = os.getcwd()
    fileList =  getPasswordFiles(dir)
    doBackUp(dir)

    newPassFile = os.getcwd() + "/newpass"
    if not os.path.exists(newPassFile):
        print "newpass文件不存在"
        return
    newPassList = getPassList(newPassFile)
    for oldFile in fileList:
        finalPassList = getPassList(oldFile)
        for newPass in newPassList:
            if newPass not in finalPassList:
                finalPassList.append(newPass)

        finalPassStr = ""
        for finalPass in finalPassList:
            #if finalPass != "":
            finalPassStr = finalPassStr + finalPass + "\n"
        with open(oldFile, "w") as f:
            f.write(finalPassStr[0:-1])
        f.close()
addNewPass()

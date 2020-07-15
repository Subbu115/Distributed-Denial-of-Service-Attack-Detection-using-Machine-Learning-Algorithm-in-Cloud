from tkinter import *
from tkinter import ttk
from struct import *
from os import system
import smtplib
import os
import sys
import signal
import csv
import time
import socket
import struct
import textwrap
import select
inputSrc = [sys.stdin]
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import webbrowser
from sklearn.externals import joblib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

data =pd.read_csv("csvfile.csv")

data.set_value(0, "Duration", 0)
data.to_csv("csvfiledur.csv", index=False)

a=data.iloc[0,12]
i=1
length=len(data)
for i in range(0,length):
	b=data.iloc[i,12]
	c=b-a
	system('clear')
	print("Processed line ",i)
	data.set_value(i,"Duration",c)
	data.to_csv("csvfiledur.csv",index=False)	

data =pd.read_csv("csvfiledur.csv")

data.drop('Time Stamp', axis = 1, inplace = True)
data.to_csv("csvfiledur.csv",encoding='utf-8', index=False)

data =pd.read_csv("csvfiledur.csv")

with open('processedtestset.csv', 'w',newline='') as out:
	writer=csv.writer(out)
	writer.writerow(['protocol_type','service','src_bytes','dst_bytes','count','srv_count','same_srv_rate','ipaddress'])
testdata =pd.read_csv("processedtestset.csv")

start=0
end=2
row=0
secsplits=0
srv_count33=0
srv_count66=0
prot_count1=0
prot_count6=0
prot1srv33count=0
prot6srv33count=0
prot1srv66count=0
prot6srv66count=0
count=0
src_bytes=0
dst_bytes=0
ipaddress=[]
length=len(data)
print("")
print("Number of lines processed")
print(length)
print("")
for i in range(0,length):
	b=data.iloc[i,12]
	prot=data.iloc[i,2]
	serv=data.iloc[i,3]
	sourceip=data.iloc[i,4]
	destip=data.iloc[i,5]
	src=data.iloc[i,11]
	if(b>end):
		start=end
		end=end+2
		maxip=max(ipaddress,key=ipaddress.count)
		if(prot1srv33count!=0):
			#print("1 , 33 ,",src_bytes,",",dst_bytes,",",prot1srv33count,",",prot1srv33count,",",1.0)
			testdata.loc[row]=[1 , 33 ,src_bytes,dst_bytes,prot1srv33count,prot1srv33count,1.0,maxip]
			row=row+1
		if(prot1srv66count!=0):
			#print("1 , 66 ,",src_bytes,",",dst_bytes,",",prot1srv66count,",",prot1srv66count,",",1.0)
			testdata.loc[row]=[1 , 66 ,src_bytes,dst_bytes,prot1srv66count,prot1srv66count,1.0,maxip]
			row=row+1
		if(prot6srv33count!=0):
			#print("6 , 33 ,",src_bytes,",",dst_bytes,",",prot6srv33count,",",prot6srv33count,",",1.0)
			testdata.loc[row]=[6 , 33 ,src_bytes,dst_bytes,prot6srv33count,prot6srv33count,1.0,maxip]
			row=row+1
		if(prot6srv66count!=0):
			#print("6 , 66 ,",src_bytes,",",dst_bytes,",",prot6srv66count,",",prot6srv66count,",",1.0)
			testdata.loc[row]=[6 , 66 ,src_bytes,dst_bytes,prot6srv66count,prot6srv66count,1.0,maxip]
			row=row+1
		count=0
		srv_count=0
		srv_count1=0
		prot_count1=0
		prot_count6=0
		prot1srv33count=0
		prot6srv33count=0
		prot1srv66count=0
		prot6srv66count=0
		src_bytes=0
		ipaddress=[]
		secsplits=secsplits+1
	if(b>start and b<=end):
		if((prot==1)):
			prot_count1=prot_count1+1
		if((prot==6)):
			prot_count6=prot_count6+1
		if((serv==33)):
			srv_count33=srv_count33+1
		if((serv==66)):
			srv_count66=srv_count66+1
		if((prot==1 and serv==33)):
			prot1srv33count=prot1srv33count+1
		if((prot==1 and serv==66)):
			prot1srv66count=prot1srv66count+1
		if((prot==6 and serv==33)):
			prot6srv33count=prot6srv33count+1
		if((prot==6 and serv==66)):
			prot6srv66count=prot6srv66count+1
		if((sourceip=='192.168.2.137')):
			src_bytes=src+src_bytes
		if((sourceip!='192.168.2.137')):
			dst_bytes=src+dst_bytes            
			ipaddress.append(sourceip)
testdata[['protocol_type']] = testdata[['protocol_type']].astype(int)
testdata[['service']] = testdata[['service']].astype(int)
testdata[['src_bytes']] = testdata[['src_bytes']].astype(int)
testdata[['dst_bytes']] = testdata[['dst_bytes']].astype(int)
testdata[['count']] = testdata[['count']].astype(int)
testdata[['srv_count']] = testdata[['srv_count']].astype(int)
testdata.to_csv("processedtestset.csv",encoding='utf-8', index=False)

tester=pd.read_csv("processedtestset.csv")
array=tester.values
testsm=array[:,0:7]
DTclf=joblib.load("smurfDTree.pkl")
prediction=DTclf.predict(testsm)
#NBclf=joblib.load("smurfNbayes.pkl")
#prediction2=NBclf.predict(testsm)
#SVMclf=joblib.load("smurfSVM.pkl")
#prediction3=SVMclf.predict(testsm)
print("")
print("")
print("------------------------------------------------------------------------------")
print(" Detection using KNN with accuracy of 99.24% and precision of 0.94  ")
print("------------------------------------------------------------------------------")
print(prediction)
#print(prediction2)
#print(prediction3)
print("------------------------------------------------------------------------------")

length=len(prediction)
for i in range(0,length):
	c=prediction[i]
	tester.set_value(i,"Label",c)
	tester.to_csv("processedtestset.csv",index=False)

attackerip=[]
for i in range(0,length):
	b=tester.iloc[i,8]
	if(b==1):
		d=tester.iloc[i,7]
		attackerip.append(d)

if len(set(attackerip))!=0:
	print("")
	print("")
	print("------------------------------------------------------------------------------")
	print(" 		    IP Addresses causing DDoS attack  			     ")
	print("------------------------------------------------------------------------------")
	print(set(attackerip))
	print("------------------------------------------------------------------------------")

	ips=set(attackerip)
	ipl=list(ips)
	iptotal=len(ipl)
	fromaddr = "paulpogbatrial@gmail.com"
	toaddr = "karanv25@gmail.com"
	msg = MIMEMultipart()
	msg['From'] = fromaddr
	msg['To'] = toaddr
	msg['Subject'] = "Attack Alert"
	newl="\n"
	reg="\n\nRegards,\nTeam OpenStack"
	body = " Administrator,\n\nWe have detected DDoS attack occuring in the cloud. We are using our model with accuracy of 99.24% and with average precision of 0.94. \nFollowing IP addresses have been found out to cause DDoS attack. The policies can be added to the Firewall to block the IP addresses.\n\n "
	for i in range(0,iptotal):
	    body=body+ipl[i]
	    body=body+"\n"
	body=body+reg
	msg.attach(MIMEText(body, 'plain'))
	server = smtplib.SMTP('smtp.gmail.com', 587)
	server.ehlo()
	server.starttls()
	server.ehlo()
	server.login("paulpogbatrial@gmail.com","kletech@123")
	text = msg.as_string()
	server.sendmail(fromaddr, toaddr, text)
	print("Successfully sent email alert to the administrator.")
	print("------------------------------------------------------------------------------")

with open('alertlog.csv','w',newline='') as out:
	writer=csv.writer(out)
	writer.writerow(['IP Address','Count(2 sec)'])

test=pd.read_csv("alertlog.csv")
for i in range(0,length):
	c=tester.iloc[i,8]
	if(c==1.0):
		ipadd=tester.iloc[i,7]
		count=tester.iloc[i,4]
		test.loc[i]=[ipadd,count]

test.to_csv("alertlog.csv",encoding='utf-8', index=False)


import streamlit as st
import pandas as pd
import numpy as np

import seaborn as sns

import matplotlib.pyplot as plt

st.header("DATA CAPTURE ANALYSIS")

menu=st.sidebar.selectbox("Navigation",["Home","DataSet","Flag","Analysis"])
file=st.file_uploader("Here",type=".csv")
if menu=="Home":
    pass
elif menu=="DataSet":
    if file is not None:
        data=pd.read_csv(file)
        Cols=["Type","Version","Protocol","Source_ip","Dest_ip","Id","Source_port",
            "Dest_port","Transaction_id","Flag_QR","Flag_AA","Flag_TC","Flag_RD"
            ,"Flag_RA","Flag_Z","Flag_AD","Flag_CD","Flag_OPCODE","Flag_RCODE"
            ,"QD_COUNT","AN_COUNT","NS_COUNT","AR_COUNT","QUERY_NAME","QUERY_TYPE"
            ,"QUERY_CLASS","RR_name","ns_type","an_type","rr_name","ar_type"]
        column=data.columns
        for i in range(len(column)):
            data.rename(inplace=True,columns={column[i]:Cols[i]})
        st.markdown("### Data preview")
        st.dataframe(data)
elif menu=="Flag":
    data=pd.read_csv(file)
    Cols=["Type","Version","Protocol","Source_ip","Dest_ip","Id","Source_port",
            "Dest_port","Transaction_id","Flag_QR","Flag_AA","Flag_TC","Flag_RD"
            ,"Flag_RA","Flag_Z","Flag_AD","Flag_CD","Flag_OPCODE","Flag_RCODE"
            ,"QD_COUNT","AN_COUNT","NS_COUNT","AR_COUNT","QUERY_NAME","QUERY_TYPE"
            ,"QUERY_CLASS","RR_name","ns_type","an_type","rr_name","ar_type"]
    column=data.columns
    for i in range(len(column)):
        data.rename(inplace=True,columns={column[i]:Cols[i]})
    for ind in data.index:
        for col in range(len(data.columns)):
            if data.iloc[ind ,col]=="NAN":
                data.iloc[ind,col]=np.nan
    anal=st.selectbox("Choose flag",["select","Flag_QR","Flag_AA","Flag_TC","Flag_RD"
            ,"Flag_RA","Flag_Z","Flag_AD","Flag_CD","Flag_OPCODE","Flag_RCODE"])
    st.set_option('deprecation.showPyplotGlobalUse', False)
    if anal=="select":
        pass
    elif anal=="Flag_QR":
        sns.countplot(x="Flag_QR", data=data)
        st.pyplot()
    elif anal=="Flag_AA":
        sns.countplot(x="Flag_AA", data=data)
        st.pyplot()
    elif anal=="Flag_TC":
        sns.countplot(x="Flag_TC", data=data)
        st.pyplot()
    elif anal=="Flag_RD":
        sns.countplot(x="Flag_RD", data=data)
        st.pyplot()
    elif anal=="Flag_RA":
        sns.countplot(x="Flag_RA", data=data)
        st.pyplot()
    elif anal=="Flag_Z":
        sns.countplot(x="Flag_Z", data=data)
        st.pyplot()
    elif anal=="Flag_AD":
        sns.countplot(x="Flag_AD", data=data)
        st.pyplot()
    elif anal=="Flag_CD":
        sns.countplot(x="Flag_CD", data=data)
        st.pyplot()
    elif anal=="Flag_OPCODE":
        sns.countplot(x="Flag_OPCODE", data=data)
        st.pyplot()
    elif anal=="Flag_RCODE":
        sns.countplot(x="Flag_RCODE", data=data)
        st.pyplot()
   
elif menu=="Analysis":
    data=pd.read_csv(file)
    Cols=["Type","Version","Protocol","Source_ip","Dest_ip","Id","Source_port",
            "Dest_port","Transaction_id","Flag_QR","Flag_AA","Flag_TC","Flag_RD"
            ,"Flag_RA","Flag_Z","Flag_AD","Flag_CD","Flag_OPCODE","Flag_RCODE"
            ,"QD_COUNT","AN_COUNT","NS_COUNT","AR_COUNT","QUERY_NAME","QUERY_TYPE"
            ,"QUERY_CLASS","RR_name","ns_type","an_type","rr_name","ar_type"]
    column=data.columns
    for i in range(len(column)):
        data.rename(inplace=True,columns={column[i]:Cols[i]})
    for ind in data.index:
        for col in range(len(data.columns)):
            if data.iloc[ind ,col]=="NAN":
                data.iloc[ind,col]=np.nan
    

    anal=st.selectbox("Request vs Response",["select","TYPE","Domain"])
    if anal=="select":
        pass
    elif anal=="TYPE":
        query=data["QUERY_TYPE"].value_counts()
        query=pd.DataFrame(query)
        query.columns=["count"]
        response1=data["ns_type"].value_counts()
        response2=data["an_type"].value_counts()
        response1=response1.append(response2)
        response=pd.DataFrame(response1)
        response.columns=["count"]
        fig = plt.subplots(figsize =(10, 7))
        plt.bar(query.index,query["count"],label="request")
        plt.bar(response.index,response["count"],label="response")
        plt.legend()
        plt.show()
        st.set_option('deprecation.showPyplotGlobalUse', False)
        st.pyplot()
    
    else:
        response=data["rr_name"].value_counts()
        response=pd.DataFrame(data=response)
        response.columns=["count"]
        response["rr_name"]=response.index
        response.index=range(len(response.index))
        r=data["QUERY_NAME"].value_counts()
        request=pd.DataFrame(data=r)
        request.columns=["count"]
        request["QUERY_NAME"]=request.index
        request.index=range(len(request.index))
        request_rand=request.sample(frac=0.1)
        response_rand=response.sample(frac=0.1)
        fig=plt.subplots(figsize=(16,20))
        plt.bar(request_rand["QUERY_NAME"],request_rand["count"],label="request")
        plt.bar(response_rand["rr_name"],response_rand["count"],label="response")
        plt.xticks(rotation="vertical")
        plt.legend()
        st.set_option('deprecation.showPyplotGlobalUse', False)
        st.pyplot()
        
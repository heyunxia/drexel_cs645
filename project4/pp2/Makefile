target: mitm

JAVA            = java
JAVAC           = javac

JAVASRCS        = \
			mitm/MITMProxyServer.java \
			mitm/ConnectionDetails.java \
			mitm/CopyStreamRunnable.java \
			mitm/HTTPSProxyEngine.java \
			mitm/JSSEConstants.java \
			mitm/ProxyEngine.java \
			mitm/ProxyDataFilter.java \
			mitm/MITMPlainSocketFactory.java \
			mitm/MITMSSLSocketFactory.java \
			mitm/MITMSocketFactory.java \
			mitm/StreamThread.java \
			mitm/MITMAdminClient.java \
			mitm/MITMAdminServer.java \
			mitm/CertGenerator.java \
			mitm/OnTheFlyCertGenerator.java \
			mitm/CertTest.java \
			mitm/ServerConnection.java \
			mitm/IPasswordManager.java \
			mitm/EncryptedFileBasedPasswordManager.java \
			mitm/PasswordWriter.java \
			mitm/HackerKeyManager.java \
			mitm/StatisticsManager.java \
			mitm/PasswordWriterTest.java \
			mitm/ClientCertGenerator.java \

JAVAOBJS        = $(JAVASRCS:.java=.class)

JAVACFLAGS	= -classpath ${CLASSPATH}:.:iaik_jce.jar:junit-4.11.jar:hamcrest-core-1.3.jar

SERVERJAVAFLAGS = -Djavax.net.ssl.keyStore=keystore.jks -Djavax.net.ssl.keyStorePassword=password

CLIENTJAVAFLAGS = -Djavax.net.ssl.trustStore=keystore.jks -Djavax.net.ssl.trustStorePassword=password
CLIENTAUTHFLAGS = -userName Joe -userPassword 23456
CLIENTCMDSHUTDOWN = -cmd shutdown
CLIENTCMDSTATS = -cmd stats

CLASSPATHEXT = -classpath iaik_jce.jar

.SUFFIXES:	.class .java

.java.class: $*.java
	    $(JAVAC) $(JAVACFLAGS) $*.java;

clean:
	    rm -f mitm/*\$*.class mitm/*.class mitm/*~

mitm:    $(JAVAOBJS)

TAGS:	$(JAVASRCS)
	etags $(JAVASRCS)

test: $(JAVASRCS:.java=.class)
	$(JAVA) $(JAVACFLAGS) org.junit.runner.JUnitCore mitm.CertTest

run-server: $(JAVASRCS:.java=.class)
	$(JAVA) $(JAVACFLAGS) mitm.MITMProxyServer -keyStore keystore.jks -keyStorePassword password -outputFile logFile

run-client-stats: $(JAVASRCS:.java=.class)
	$(JAVA) $(JAVACFLAGS) $(CLIENTJAVAFLAGS) mitm.MITMAdminClient $(CLIENTAUTHFLAGS) $(CLIENTCMDSTATS)

run-client-shutdown: $(JAVASRCS:.java=.class)
	$(JAVA) $(JAVACFLAGS) $(CLIENTJAVAFLAGS) mitm.MITMAdminClient $(CLIENTAUTHFLAGS) $(CLIENTCMDSHUTDOWN)

run-passwordcreator: $(JAVASRCS:.java=.class)
	$(JAVA) mitm.PasswordWriter -filePath userNames

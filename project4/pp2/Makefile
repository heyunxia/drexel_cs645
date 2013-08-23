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

JAVAOBJS        = $(JAVASRCS:.java=.class)

JAVACFLAGS	= -classpath ${CLASSPATH}:.:iaik_jce.jar:junit-4.11.jar:hamcrest-core-1.3.jar

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

<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
	<xsl:output method="text" version="1.0" encoding="UTF-8" indent="yes"/>
	<xsl:template match="/">
		<xsl:for-each select="//xenc:EncryptedData">
			<xsl:for-each select="./ds:KeyInfo/xenc:EncryptedKey">
				<xsl:text>####KEYNAME:=</xsl:text>
				<xsl:value-of select="./ds:KeyInfo/ds:KeyName"/>
				<xsl:text>####ENCRYPTEDKEY:=</xsl:text>
				<xsl:value-of select="./xenc:CipherData/xenc:CipherValue"/>
			</xsl:for-each>
			<xsl:text>#-#-#-#-#-#-#-#-#</xsl:text>
			<xsl:value-of select="./xenc:CipherData/xenc:CipherValue"/>
		</xsl:for-each>
	</xsl:template>
</xsl:stylesheet>

<?xml version="1.0" encoding="UTF-8"?>
<!--
Copyright 2011 Damian Murphy <murff@warlock.org>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
-->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:fn="http://www.w3.org/2004/10/xpath-functions" xmlns:xdt="http://www.w3.org/2004/10/xpath-datatypes" xmlns:itk="urn:nhs-itk:ns:201005">
	<xsl:output method="xml" version="1.0" encoding="UTF-8" indent="yes"/>
	<xsl:template match="/">
		<xsl:comment>
		<xsl:text>S#</xsl:text><xsl:value-of select="//itk:DistributionEnvelope/itk:header/@service"/><xsl:text>!</xsl:text>		
		<xsl:text>T#</xsl:text><xsl:value-of select="//itk:DistributionEnvelope/itk:header/@trackingid"/><xsl:text>!</xsl:text>		
		<xsl:for-each select="//itk:DistributionEnvelope/itk:header/itk:addresslist/itk:address">
			<xsl:text>A#</xsl:text>
			<xsl:if test="./@type">
				<xsl:value-of select="./@type"/>
			</xsl:if>
			<xsl:text>#</xsl:text><xsl:value-of select="./@uri"/><xsl:text>!</xsl:text>
		</xsl:for-each>
		<xsl:for-each select="//itk:DistributionEnvelope/itk:header/itk:auditIdentity/itk:id">
			<xsl:text>I#</xsl:text>
			<xsl:if test="./@type">
				<xsl:value-of select="./@type"/>
			</xsl:if>
			<xsl:text>#</xsl:text><xsl:value-of select="./@uri"/><xsl:text>!</xsl:text>
		</xsl:for-each>
		<xsl:text>R#</xsl:text>
		<xsl:value-of select="//itk:DistributionEnvelope/itk:header/itk:senderAddress/@type"/>
		<xsl:text>#</xsl:text>
		<xsl:value-of select="//itk:DistributionEnvelope/itk:header/itk:senderAddress/@uri"/>
		<xsl:text>!</xsl:text>
		<xsl:for-each select="//itk:DistributionEnvelope/itk:header/itk:handlingSpecification/itk:spec">
			<xsl:text>H#</xsl:text>
			<xsl:value-of select="./@key"/>
			<xsl:text>#</xsl:text><xsl:value-of select="./@value"/><xsl:text>!</xsl:text>
		</xsl:for-each>
		</xsl:comment>
		<!-- <xsl:copy-of select="//itk:DistributionEnvelope" copy-namespaces="yes"/> -->
    <xsl:copy-of select="//itk:DistributionEnvelope"/>
	</xsl:template>
</xsl:stylesheet>

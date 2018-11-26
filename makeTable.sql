/* Script for creating the table for storing found certificates. Replace YOURDATABASENAME with an existing database */
USE [YOURDATABASENAME]
GO

SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[certificatesLog](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[hostnameFQDN] [nvarchar](500) NULL,
	[endpoint] [nvarchar](500) NULL,
	[port] [nvarchar](50) NULL,
	[dnsServerIP] [nvarchar](50) NULL,
	[dnsServerZone] [nvarchar](500) NULL,
	[serialNumber] [nvarchar](2000) NULL,
	[issuerName] [nvarchar](1000) NULL,
	[issuedTo] [nvarchar](1000) NULL,
	[subjectName] [nvarchar](1000) NULL,
	[validFromDate] [datetime] NULL,
	[expiresDate] [datetime] NULL,
	[expiresDays] [int] NULL,
	[signatureAlgorithm] [nvarchar](500) NULL,
	[subjectAlternativeNames] [nvarchar](max) NULL,
	[detectedDate] [datetime] NOT NULL,
	[lastScannedDate] [datetime] NULL,
	[ignore] [bit] NOT NULL,
	[expireWarning1Sent] [datetime] NULL,
	[expireWarning2Sent] [datetime] NULL,
	[expireWarning4Sent] [datetime] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

ALTER TABLE [dbo].[certificatesLog] ADD  CONSTRAINT [DF_certificatesLog_certificateFirstDetected]  DEFAULT (getdate()) FOR [detectedDate]
GO

ALTER TABLE [dbo].[certificatesLog] ADD  CONSTRAINT [DF_certificatesLog_ignore]  DEFAULT ((0)) FOR [ignore]
GO

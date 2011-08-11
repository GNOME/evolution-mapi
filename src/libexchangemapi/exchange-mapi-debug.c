/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the program; if not, see <http://www.gnu.org/licenses/>
 *
 *
 * Copyright (C) 2011 Red Hat, Inc. (www.redhat.com)
 *
 */

#include <stdarg.h>

#include "exchange-mapi-debug.h"

gboolean
exchange_mapi_debug_is_enabled (void)
{
	static gchar enabled = -1;

	if (enabled == -1)
		enabled = g_getenv ("EXCHANGEMAPI_DEBUG") != NULL ? 1 : 0;

	return enabled == 1;
}

void
exchange_mapi_debug_print (const gchar *format, ...)
{
	va_list args;

	g_return_if_fail (format != NULL);

	if (!exchange_mapi_debug_is_enabled ())
		return;

	va_start (args, format);
	vfprintf (stdout, format, args);
	va_end (args);

	fprintf (stdout, "\n");
	fflush (stdout);
}

static void
dump_bin (const uint8_t *bin, uint32_t bin_sz, const gchar *line_prefix)
{
	gint k, l, last;

	if (!bin) {
		g_print ("NULL");
		return;
	}

	g_print ("%s", line_prefix);

	last = 0;
	for (k = 0; k < bin_sz; k++) {
		if ((k > 0 && (k % 16) == 0)) {
			g_print ("  ");
			for (l = last; l < k; l++) {
				uint8_t u8 = bin[l];

				if ((l % 8) == 0)
					g_print (" ");
				if (u8 <= 32 || u8 >= 128)
					g_print (".");
				else
					g_print ("%c", u8);
			}

			last = l;
			g_print ("\n%s", line_prefix);
		} else if (k > 0 && (k % 8) == 0) {
			g_print ("  ");
		}
		g_print (" %02X", bin[k]);
	}

	if (last < k) {
		l = k;

		while ((l % 16) != 0) {
			g_print ("   ");
			if (l > 0 && (l % 8) == 0)
				g_print ("  ");
			l++;
		}

		g_print ("  ");
		for (l = last; l < k; l++) {
			uint8_t u8 = bin[l];

			if ((l % 8) == 0)
				g_print (" ");
			if (u8 <= 32 || u8 >= 128)
				g_print (".");
			else
				g_print ("%c", u8);
		}
	}
}

static const gchar *
get_namedid_name (ExchangeMapiConnection *conn, mapi_id_t fid, uint32_t proptag)
{
	if (conn)
		proptag = exchange_mapi_connection_unresolve_proptag_to_nameid (conn, fid, proptag);

	if (proptag == MAPI_E_RESERVED)
		return NULL;

	switch (proptag) {
	#define cs(x) case x: return #x;
	cs (PidLidAddressBookProviderArrayType)
	cs (PidLidAddressBookProviderEmailList)
	cs (PidLidAddressCountryCode)
	cs (PidLidAnniversaryEventEntryId)
	cs (PidLidAutoLog)
	cs (PidLidBirthdayEventEntryId)
	cs (PidLidBirthdayLocal)
	cs (PidLidBusinessCardCardPicture)
	cs (PidLidBusinessCardDisplayDefinition)
	cs (PidLidContactCharacterSet)
	cs (PidLidContactItemData)
	cs (PidLidContactUserField1)
	cs (PidLidContactUserField2)
	cs (PidLidContactUserField3)
	cs (PidLidContactUserField4)
	cs (PidLidDepartment)
	cs (PidLidDistributionListChecksum)
	cs (PidLidDistributionListMembers)
	cs (PidLidDistributionListName)
	cs (PidLidDistributionListOneOffMembers)
	cs (PidLidDistributionListStream)
	cs (PidLidEmail1AddressType)
	cs (PidLidEmail1DisplayName)
	cs (PidLidEmail1EmailAddress)
	cs (PidLidEmail1OriginalDisplayName)
	cs (PidLidEmail1OriginalEntryId)
	cs (PidLidEmail1RichTextFormat)
	cs (PidLidEmail2AddressType)
	cs (PidLidEmail2DisplayName)
	cs (PidLidEmail2EmailAddress)
	cs (PidLidEmail2OriginalDisplayName)
	cs (PidLidEmail2OriginalEntryId)
	cs (PidLidEmail2RichTextFormat)
	cs (PidLidEmail3AddressType)
	cs (PidLidEmail3DisplayName)
	cs (PidLidEmail3EmailAddress)
	cs (PidLidEmail3OriginalDisplayName)
	cs (PidLidEmail3OriginalEntryId)
	cs (PidLidEmail3RichTextFormat)
	cs (PidLidEmailList)
	cs (PidLidFax1AddressType)
	cs (PidLidFax1EmailAddress)
	cs (PidLidFax1OriginalDisplayName)
	cs (PidLidFax1OriginalEntryId)
	cs (PidLidFax2AddressType)
	cs (PidLidFax2EmailAddress)
	cs (PidLidFax2OriginalDisplayName)
	cs (PidLidFax2OriginalEntryId)
	cs (PidLidFax3AddressType)
	cs (PidLidFax3EmailAddress)
	cs (PidLidFax3OriginalDisplayName)
	cs (PidLidFax3OriginalEntryId)
	cs (PidLidFileUnder)
	cs (PidLidFileUnderId)
	cs (PidLidFileUnderList)
	cs (PidLidFreeBusyLocation)
	cs (PidLidHasPicture)
	cs (PidLidHomeAddress)
	cs (PidLidHomeAddressCountryCode)
	cs (PidLidHtml)
	cs (PidLidInstantMessagingAddress)
	cs (PidLidOtherAddress)
	cs (PidLidOtherAddressCountryCode)
	cs (PidLidPostalAddressId)
	cs (PidLidReferredBy)
	cs (PidLidWeddingAnniversaryLocal)
	cs (PidLidWorkAddress)
	cs (PidLidWorkAddressCity)
	cs (PidLidWorkAddressCountry)
	cs (PidLidWorkAddressCountryCode)
	cs (PidLidWorkAddressPostalCode)
	cs (PidLidWorkAddressPostOfficeBox)
	cs (PidLidWorkAddressState)
	cs (PidLidYomiCompanyName)
	cs (PidLidYomiFirstName)
	cs (PidLidYomiLastName)
	cs (PidLidAllAttendeesString)
	cs (PidLidAllowExternalCheck)
	cs (PidLidAppointmentAuxiliaryFlags)
	cs (PidLidAppointmentColor)
	cs (PidLidAppointmentCounterProposal)
	cs (PidLidAppointmentDuration)
	cs (PidLidAppointmentEndDate)
	cs (PidLidAppointmentEndTime)
	cs (PidLidAppointmentEndWhole)
	cs (PidLidAppointmentLastSequence)
	cs (PidLidAppointmentNotAllowPropose)
	cs (PidLidAppointmentProposalNumber)
	cs (PidLidAppointmentProposedDuration)
	cs (PidLidAppointmentProposedEndWhole)
	cs (PidLidAppointmentProposedStartWhole)
	cs (PidLidAppointmentRecur)
	cs (PidLidAppointmentReplyName)
	cs (PidLidAppointmentReplyTime)
	cs (PidLidAppointmentSequence)
	cs (PidLidAppointmentSequenceTime)
	cs (PidLidAppointmentStartDate)
	cs (PidLidAppointmentStartTime)
	cs (PidLidAppointmentStartWhole)
	cs (PidLidAppointmentStateFlags)
	cs (PidLidAppointmentSubType)
	cs (PidLidAppointmentTimeZoneDefinitionEndDisplay)
	cs (PidLidAppointmentTimeZoneDefinitionRecur)
	cs (PidLidAppointmentTimeZoneDefinitionStartDisplay)
	cs (PidLidAppointmentUnsendableRecipients)
	cs (PidLidAppointmentUpdateTime)
	cs (PidLidAutoFillLocation)
	cs (PidLidAutoStartCheck)
	cs (PidLidBusyStatus)
	cs (PidLidCcAttendeesString)
	cs (PidLidChangeHighlight)
	cs (PidLidClipEnd)
	cs (PidLidClipStart)
	cs (PidLidCollaborateDoc)
	cs (PidLidConferencingCheck)
	cs (PidLidConferencingType)
	cs (PidLidDirectory)
	cs (PidLidExceptionReplaceTime)
	cs (PidLidFExceptionalAttendees)
	cs (PidLidFExceptionalBody)
	cs (PidLidFInvited)
	cs (PidLidForwardInstance)
	cs (PidLidForwardNotificationRecipients)
	cs (PidLidFOthersAppointment)
	cs (PidLidInboundICalStream)
	cs (PidLidIntendedBusyStatus)
	cs (PidLidLinkedTaskItems)
	cs (PidLidLocation)
	cs (PidLidMeetingWorkspaceUrl)
	cs (PidLidNetShowUrl)
	cs (PidLidOnlinePassword)
	cs (PidLidOrganizerAlias)
	cs (PidLidOriginalStoreEntryId)
	cs (PidLidOwnerName)
	cs (PidLidRecurrencePattern)
	cs (PidLidRecurrenceType)
	cs (PidLidRecurring)
	cs (PidLidResponseStatus)
	cs (PidLidSingleBodyICal)
	cs (PidLidTimeZoneDescription)
	cs (PidLidTimeZoneStruct)
	cs (PidLidToAttendeesString)
	cs (PidLidClientIntent)
	cs (PidLidServerProcessed)
	cs (PidLidServerProcessingActions)
	cs (PidLidAgingDontAgeMe)
	cs (PidLidAutoProcessState)
	cs (PidLidBilling)
	cs (PidLidClassification)
	cs (PidLidClassificationDescription)
	cs (PidLidClassificationGuid)
	cs (PidLidClassificationKeep)
	cs (PidLidClassified)
	cs (PidLidCommonEnd)
	cs (PidLidCommonStart)
	cs (PidLidCompanies)
	cs (PidLidContactLinkEntry)
	cs (PidLidContactLinkName)
	cs (PidLidContactLinkSearchKey)
	cs (PidLidContacts)
	cs (PidLidConversationActionLastAppliedTime)
	cs (PidLidConversationActionMaxDeliveryTime)
	cs (PidLidConversationActionMoveFolderEid)
	cs (PidLidConversationActionMoveStoreEid)
	cs (PidLidConversationActionVersion)
	cs (PidLidConversationProcessed)
	cs (PidLidCurrentVersion)
	cs (PidLidCurrentVersionName)
	cs (PidLidDayOfMonth)
	cs (PidLidFlagRequest)
	cs (PidLidFlagString)
	cs (PidLidICalendarDayOfWeekMask)
	cs (PidLidInfoPathFormName)
	cs (PidLidInternetAccountName)
	cs (PidLidInternetAccountStamp)
	cs (PidLidMonthOfYear)
	cs (PidLidNoEndDateFlag)
	cs (PidLidNonSendableBcc)
	cs (PidLidNonSendableCc)
	cs (PidLidNonSendableTo)
	cs (PidLidNonSendBccTrackStatus)
	cs (PidLidNonSendCcTrackStatus)
	cs (PidLidNonSendToTrackStatus)
	cs (PidLidOccurrences)
	cs (PidLidPrivate)
	cs (PidLidPromptSendUpdate)
	cs (PidLidRecurrenceDuration)
	cs (PidLidReferenceEntryId)
	cs (PidLidReminderDelta)
	cs (PidLidReminderFileParameter)
	cs (PidLidReminderOverride)
	cs (PidLidReminderPlaySound)
	cs (PidLidReminderSet)
	cs (PidLidReminderSignalTime)
	cs (PidLidReminderTime)
	cs (PidLidReminderTimeDate)
	cs (PidLidReminderTimeTime)
	cs (PidLidReminderType)
	cs (PidLidRemoteStatus)
	cs (PidLidSideEffects)
	cs (PidLidSmartNoAttach)
	cs (PidLidSpamOriginalFolder)
	cs (PidLidTaskGlobalId)
	cs (PidLidTaskMode)
	cs (PidLidToDoOrdinalDate)
	cs (PidLidToDoSubOrdinal)
	cs (PidLidToDoTitle)
	cs (PidLidUseTnef)
	cs (PidLidValidFlagStringProof)
	cs (PidLidVerbResponse)
	cs (PidLidVerbStream)
	cs (PidLidLogDocumentPosted)
	cs (PidLidLogDocumentPrinted)
	cs (PidLidLogDocumentRouted)
	cs (PidLidLogDocumentSaved)
	cs (PidLidLogDuration)
	cs (PidLidLogEnd)
	cs (PidLidLogFlags)
	cs (PidLidLogStart)
	cs (PidLidLogType)
	cs (PidLidLogTypeDesc)
	cs (PidLidAppointmentMessageClass)
	cs (PidLidAttendeeCriticalChange)
	cs (PidLidCalendarType)
	cs (PidLidCleanGlobalObjectId)
	cs (PidLidDayInterval)
	cs (PidLidDelegateMail)
	cs (PidLidEndRecurrenceDate)
	cs (PidLidEndRecurrenceTime)
	cs (PidLidGlobalObjectId)
	cs (PidLidIsException)
	cs (PidLidIsRecurring)
	cs (PidLidIsSilent)
	cs (PidLidMeetingType)
	cs (PidLidMonthInterval)
	cs (PidLidMonthOfYearMask)
	cs (PidLidOldLocation)
	cs (PidLidOldRecurrenceType)
	cs (PidLidOldWhenEndWhole)
	cs (PidLidOldWhenStartWhole)
	cs (PidLidOptionalAttendees)
	cs (PidLidOwnerCriticalChange)
	cs (PidLidRequiredAttendees)
	cs (PidLidResourceAttendees)
	cs (PidLidStartRecurrenceDate)
	cs (PidLidStartRecurrenceTime)
	cs (PidLidTimeZone)
	cs (PidLidWeekInterval)
	cs (PidLidWhere)
	cs (PidLidYearInterval)
	cs (PidLidNoteColor)
	cs (PidLidNoteHeight)
	cs (PidLidNoteWidth)
	cs (PidLidNoteX)
	cs (PidLidNoteY)
	cs (PidLidPostRssChannel)
	cs (PidLidPostRssChannelLink)
	cs (PidLidPostRssItemGuid)
	cs (PidLidPostRssItemHash)
	cs (PidLidPostRssItemLink)
	cs (PidLidPostRssItemXml)
	cs (PidLidPostRssSubscription)
	cs (PidLidSharingAnonymity)
	cs (PidLidSharingBindingEntryId)
	cs (PidLidSharingBrowseUrl)
	cs (PidLidSharingCapabilities)
	cs (PidLidSharingConfigurationUrl)
	cs (PidLidSharingDataRangeEnd)
	cs (PidLidSharingDataRangeStart)
	cs (PidLidSharingDetail)
	cs (PidLidSharingExtensionXml)
	cs (PidLidSharingFilter)
	cs (PidLidSharingFlags)
	cs (PidLidSharingFlavor)
	cs (PidLidSharingFolderEntryId)
	cs (PidLidSharingIndexEntryId)
	cs (PidLidSharingInitiatorEntryId)
	cs (PidLidSharingInitiatorName)
	cs (PidLidSharingInitiatorSmtp)
	cs (PidLidSharingInstanceGuid)
	cs (PidLidSharingLastAutoSyncTime)
	cs (PidLidSharingLastSyncTime)
	cs (PidLidSharingLocalComment)
	cs (PidLidSharingLocalLastModificationTime)
	cs (PidLidSharingLocalName)
	cs (PidLidSharingLocalPath)
	cs (PidLidSharingLocalStoreUid)
	cs (PidLidSharingLocalType)
	cs (PidLidSharingLocalUid)
	cs (PidLidSharingOriginalMessageEntryId)
	cs (PidLidSharingParentBindingEntryId)
	cs (PidLidSharingParticipants)
	cs (PidLidSharingPermissions)
	cs (PidLidSharingProviderExtension)
	cs (PidLidSharingProviderGuid)
	cs (PidLidSharingProviderName)
	cs (PidLidSharingProviderUrl)
	cs (PidLidSharingRangeEnd)
	cs (PidLidSharingRangeStart)
	cs (PidLidSharingReciprocation)
	cs (PidLidSharingRemoteByteSize)
	cs (PidLidSharingRemoteComment)
	cs (PidLidSharingRemoteCrc)
	cs (PidLidSharingRemoteLastModificationTime)
	cs (PidLidSharingRemoteMessageCount)
	cs (PidLidSharingRemoteName)
	cs (PidLidSharingRemotePass)
	cs (PidLidSharingRemotePath)
	cs (PidLidSharingRemoteStoreUid)
	cs (PidLidSharingRemoteType)
	cs (PidLidSharingRemoteUid)
	cs (PidLidSharingRemoteUser)
	cs (PidLidSharingRemoteVersion)
	cs (PidLidSharingResponseTime)
	cs (PidLidSharingResponseType)
	cs (PidLidSharingRoamLog)
	cs (PidLidSharingStart)
	cs (PidLidSharingStatus)
	cs (PidLidSharingStop)
	cs (PidLidSharingSyncFlags)
	cs (PidLidSharingSyncInterval)
	cs (PidLidSharingTimeToLive)
	cs (PidLidSharingTimeToLiveAuto)
	cs (PidLidSharingWorkingHoursDays)
	cs (PidLidSharingWorkingHoursEnd)
	cs (PidLidSharingWorkingHoursStart)
	cs (PidLidSharingWorkingHoursTimeZone)
	cs (PidLidPercentComplete)
	cs (PidLidTaskAcceptanceState)
	cs (PidLidTaskAccepted)
	cs (PidLidTaskActualEffort)
	cs (PidLidTaskAssigner)
	cs (PidLidTaskAssigners)
	cs (PidLidTaskComplete)
	cs (PidLidTaskCustomFlags)
	cs (PidLidTaskDateCompleted)
	cs (PidLidTaskDeadOccurrence)
	cs (PidLidTaskDueDate)
	cs (PidLidTaskEstimatedEffort)
	cs (PidLidTaskFCreator)
	cs (PidLidTaskFFixOffline)
	cs (PidLidTaskFRecurring)
	cs (PidLidTaskHistory)
	cs (PidLidTaskLastDelegate)
	cs (PidLidTaskLastUpdate)
	cs (PidLidTaskLastUser)
	cs (PidLidTaskMultipleRecipients)
	cs (PidLidTaskNoCompute)
	cs (PidLidTaskOrdinal)
	cs (PidLidTaskOwner)
	cs (PidLidTaskOwnership)
	cs (PidLidTaskRecurrence)
	cs (PidLidTaskResetReminder)
	cs (PidLidTaskRole)
	cs (PidLidTaskStartDate)
	cs (PidLidTaskState)
	cs (PidLidTaskStatus)
	cs (PidLidTaskStatusOnComplete)
	cs (PidLidTaskUpdates)
	cs (PidLidTaskVersion)
	cs (PidLidTeamTask)
	cs (PidLidTrustRecipientHighlights)
	cs (PidLidCategories)
	cs (PidNameInstantMessagingAddress2)
	cs (PidNameInstantMessagingAddress3)
	cs (PidNameAttachmentMacContentType)
	cs (PidNameAttachmentMacInfo)
	cs (PidNameOriginalSpamConfidenceLevel)
	cs (PidNameAudioNotes)
	cs (PidNameAutomaticSpeechRecognitionData)
	cs (PidNameOutlookProtectionRuleTimestamp)
	cs (PidNameXUnifiedMessagingPartnerAssignedId)
	cs (PidNameXUnifiedMessagingPartnerContent)
	cs (PidNameXUnifiedMessagingPartnerContext)
	cs (PidNameXUnifiedMessagingPartnerStatus)
	cs (PidNameAcceptLanguage)
	cs (PidNameApprovalAllowedDecisionMakers)
	cs (PidNameApprovalRequestor)
	cs (PidNameApproved)
	cs (PidNameAuthenticatedAs)
	cs (PidNameAuthenticatedDomain)
	cs (PidNameAuthenticatedMechanism)
	cs (PidNameAuthenticatedSource)
	cs (PidNameBcc)
	cs (PidNameCc)
	cs (PidNameContentBase)
	cs (PidNameContentClass)
	cs (PidNameContentDisposition)
	cs (PidNameContentID)
	cs (PidNameContentLanguage)
	cs (PidNameContentLocation)
	cs (PidNameContentTransferEncoding)
	cs (PidNameContentType)
	cs (PidNameControl)
	cs (PidNameCrossReference)
	cs (PidNameDisposition)
	cs (PidNameDispositionNotificationTo)
	cs (PidNameDistribution)
	cs (PidNameExpires)
	cs (PidNameExpiryDate)
	cs (PidNameFollowupTo)
	cs (PidNameFrom)
	cs (PidNameImportance)
	cs (PidNameInReplyTo)
	cs (PidNameInternetComment)
	cs (PidNameInternetKeywords)
	cs (PidNameInternetSubject)
	cs (PidNameLines)
	cs (PidNameMessageId)
	cs (PidNameMimeVersion)
	cs (PidNameNewsgroups)
	cs (PidNameNntpPostingHost)
	cs (PidNameOrganization)
	cs (PidNameOriginalRecipient)
	cs (PidNameOutlookProtectionRuleOverridden)
	cs (PidNameOutlookProtectionRuleVersion)
	cs (PidNamePath)
	cs (PidNamePostingVersion)
	cs (PidNamePriority)
	cs (PidNameReceived)
	cs (PidNameReferences)
	cs (PidNameRelayVersion)
	cs (PidNameReplyBy)
	cs (PidNameReplyTo)
	cs (PidNameReturnPath)
	cs (PidNameReturnReceiptTo)
	cs (PidNameRightsProtectMessage)
	cs (PidNameSender)
	cs (PidNameSensitivity)
	cs (PidNameSummary)
	cs (PidNameThreadIndex)
	cs (PidNameThreadTopic)
	cs (PidNameTo)
	cs (PidNameXCallId)
	cs (PidNameXFaxNumberOfPages)
	cs (PidNameXMailer)
	cs (PidNameXMessageCompleted)
	cs (PidNameXMessageFlag)
	cs (PidNameXRequireProtectedPlayOnPhone)
	cs (PidNameXSenderTelephoneNumber)
	cs (PidNameXSharingBrowseUrl)
	cs (PidNameXSharingCapabilities)
	cs (PidNameXSharingConfigUrl)
	cs (PidNameXSharingExendedCaps)
	cs (PidNameXSharingFlavor)
	cs (PidNameXSharingInstanceGuid)
	cs (PidNameXSharingLocalType)
	cs (PidNameXSharingProviderGuid)
	cs (PidNameXSharingProviderName)
	cs (PidNameXSharingProviderUrl)
	cs (PidNameXSharingRemoteName)
	cs (PidNameXSharingRemotePath)
	cs (PidNameXSharingRemoteStoreUid)
	cs (PidNameXSharingRemoteType)
	cs (PidNameXSharingRemoteUid)
	cs (PidNameXUnsent)
	cs (PidNameXVoiceMessageAttachmentOrder)
	cs (PidNameXVoiceMessageDuration)
	cs (PidNameXVoiceMessageSenderName)
	cs (PidNameApplicationName)
	cs (PidNameAuthor)
	cs (PidNameByteCount)
	cs (PidNameCalendarAttendeeRole)
	cs (PidNameCalendarBusystatus)
	cs (PidNameCalendarContact)
	cs (PidNameCalendarContactUrl)
	cs (PidNameCalendarCreated)
	cs (PidNameCalendarDescriptionUrl)
	cs (PidNameCalendarDuration)
	cs (PidNameCalendarExceptionDate)
	cs (PidNameCalendarExceptionRule)
	cs (PidNameCalendarGeoLatitude)
	cs (PidNameCalendarGeoLongitude)
	cs (PidNameCalendarInstanceType)
	cs (PidNameCalendarIsOrganizer)
	cs (PidNameCalendarLastModified)
	cs (PidNameCalendarLocationUrl)
	cs (PidNameCalendarMeetingStatus)
	cs (PidNameCalendarMethod)
	cs (PidNameCalendarProductId)
	cs (PidNameCalendarRecurrenceIdRange)
	cs (PidNameCalendarReminderOffset)
	cs (PidNameCalendarResources)
	cs (PidNameCalendarRsvp)
	cs (PidNameCalendarSequence)
	cs (PidNameCalendarTimeZone)
	cs (PidNameCalendarTimeZoneId)
	cs (PidNameCalendarTransparent)
	cs (PidNameCalendarUid)
	cs (PidNameCalendarVersion)
	cs (PidNameCategory)
	cs (PidNameCharacterCount)
	cs (PidNameComments)
	cs (PidNameCompany)
	cs (PidNameContactsAlternateRecipient)
	cs (PidNameContactsCountry)
	cs (PidNameContactsEmail1)
	cs (PidNameContactsEmail2)
	cs (PidNameContactsEmail3)
	cs (PidNameContactsFileAs)
	cs (PidNameContactsFileasId)
	cs (PidNameContactsHomeLatitude)
	cs (PidNameContactsHomeLongitude)
	cs (PidNameContactsHomeTimeZone)
	cs (PidNameContactsMapUrl)
	cs (PidNameContactsOtherCountryCode)
	cs (PidNameContactsOtherPager)
	cs (PidNameContactsOtherTimeZone)
	cs (PidNameContactsProxyAddresses)
	cs (PidNameContactsSecretaryUrl)
	cs (PidNameContactsSourceUrl)
	cs (PidNameCreateDateTimeReadOnly)
	cs (PidNameDavGetContentType)
	cs (PidNameDavId)
	cs (PidNameDavIsCollection)
	cs (PidNameDavIsStructuredDocument)
	cs (PidNameDavParentName)
	cs (PidNameDavResourceType)
	cs (PidNameDavSearchRequest)
	cs (PidNameDavSearchType)
	cs (PidNameDavUid)
	cs (PidNameDocumentParts)
	cs (PidNameEditTime)
	cs (PidNameExchangeIntendedBusyStatus)
	cs (PidNameExchangeJunkEmailMoveStamp)
	cs (PidNameExchangeModifyExceptionStructure)
	cs (PidNameExchangeNoModifyExceptions)
	cs (PidNameExchangePatternEnd)
	cs (PidNameExchangePatternStart)
	cs (PidNameExchangePublicFolderEmailAddress)
	cs (PidNameExchangeReminderInterval)
	cs (PidNameExchDatabaseSchema)
	cs (PidNameExchDataExpectedContentClass)
	cs (PidNameExchDataSchemaCollectionReference)
	cs (PidNameHeadingPairs)
	cs (PidNameHiddenCount)
	cs (PidNameHttpmailCalendar)
	cs (PidNameHttpmailCc)
	cs (PidNameHttpmailContacts)
	cs (PidNameHttpmailContentMediaType)
	cs (PidNameHttpmailFrom)
	cs (PidNameHttpmailFromEmail)
	cs (PidNameHttpmailHtmlDescription)
	cs (PidNameHttpmailOutbox)
	cs (PidNameHttpmailSendMessage)
	cs (PidNameHttpmailSubmitted)
	cs (PidNameHttpmailTo)
	cs (PidNameICalendarRecurrenceDate)
	cs (PidNameICalendarRecurrenceRule)
	cs (PidNameKeywords)
	cs (PidNameLastAuthor)
	cs (PidNameLastPrinted)
	cs (PidNameLastSaveDateTime)
	cs (PidNameLineCount)
	cs (PidNameLinksDirty)
	cs (PidNameMailSubmissionUri)
	cs (PidNameManager)
	cs (PidNameMultimediaClipCount)
	cs (PidNameNoteCount)
	cs (PidNameOMSAccountGuid)
	cs (PidNameOMSMobileModel)
	cs (PidNameOMSScheduleTime)
	cs (PidNameOMSServiceType)
	cs (PidNameOMSSourceType)
	cs (PidNamePageCount)
	cs (PidNameParagraphCount)
	cs (PidNamePhishingStamp)
	cs (PidNamePresentationFormat)
	cs (PidNameQuarantineOriginalSender)
	cs (PidNameRevisionNumber)
	cs (PidNameRightsManagementLicense)
	cs (PidNameScale)
	cs (PidNameSecurity)
	cs (PidNameSlideCount)
	cs (PidNameSubject)
	cs (PidNameTemplate)
	cs (PidNameThumbnail)
	cs (PidNameTitle)
	cs (PidNameWordCount)
	#undef cs
	}

	return NULL;
}

void
exchange_mapi_debug_dump_properties (ExchangeMapiConnection *conn, mapi_id_t fid, struct mapi_SPropValue_array *properties)
{
	gint i = 0;

	g_return_if_fail (properties != NULL);

	for (i = 0; i < properties->cValues; i++) {
		struct mapi_SPropValue *lpProp = &properties->lpProps[i];
		const gchar *tmp =  get_proptag_name (lpProp->ulPropTag);
		gchar t_str[26];
		gint j = 0;

		if (!tmp || !*tmp)
			tmp = get_namedid_name (conn, fid, lpProp->ulPropTag);

		if (tmp && *tmp)
			g_print ("   %s   ",tmp);
		else
			g_print ("   0x%08X   ", lpProp->ulPropTag);
		switch (lpProp->ulPropTag & 0xFFFF) {
		case PT_UNSPECIFIED:
			g_print (" PT_UNSPECIFIED");
			break;
		case PT_NULL:
			g_print (" PT_NULL");
			break;
		case PT_BOOLEAN:
			g_print (" (bool) - %d", (bool) lpProp->value.b);
			break;
		case PT_I2:
			g_print (" (uint16_t) - %d", lpProp->value.i);
			break;
		case PT_LONG:
			g_print (" (long) - %u", lpProp->value.l);
			break;
		case PT_FLOAT:
			g_print (" PT_FLOAT");
			break;
		case PT_DOUBLE:
			g_print (" (double) -  %lf", (double)lpProp->value.dbl);
			break;
		case PT_CURRENCY:
			g_print (" PT_CURRENCY");
			break;
		case PT_APPTIME:
			g_print (" PT_APPTIME");
		case PT_I8:
			g_print (" (gint) - 0x%016" G_GINT64_MODIFIER "X", lpProp->value.d);
			break;
		case PT_SYSTIME: {
				struct timeval t;
				struct tm tm;
				if (get_mapi_SPropValue_array_date_timeval (&t, properties, lpProp->ulPropTag) == MAPI_E_SUCCESS) {
					gmtime_r (&(t.tv_sec), &tm);
					strftime (t_str, 26, "%Y-%m-%dT%H:%M:%SZ", &tm);
					g_print (" (struct FILETIME *) - %p   (struct timeval) %s", &lpProp->value.ft, t_str);
				}
			}
			break;
		case PT_ERROR:
			g_print (" (error) - "/* , lpProp->value.err */);
			break;
		case PT_STRING8:
			g_print (" (string) - %s", lpProp->value.lpszA ? lpProp->value.lpszA : "null");
			break;
		case PT_UNICODE:
			if (lpProp)
				g_print (" (unicodestring) - %s", lpProp->value.lpszW ? lpProp->value.lpszW : lpProp->value.lpszA ? lpProp->value.lpszA : "null");
			break;
		case PT_OBJECT:
			g_print (" PT_OBJECT");
			break;
		case PT_CLSID:
			g_print (" PT_CLSID");
			break;
		case PT_SVREID:
			g_print (" PT_SVREID");
			break;
		case PT_SRESTRICT:
			g_print (" PT_SRESTRICT");
			break;
		case PT_ACTIONS:
			g_print (" PT_ACTIONS");
			break;
		case PT_BINARY:
			g_print (" (struct SBinary_short *) - %p Binary data follows (size %d): \n", &lpProp->value.bin, lpProp->value.bin.cb);
			dump_bin (lpProp->value.bin.lpb, lpProp->value.bin.cb, "        ");
			break;
		case PT_MV_STRING8:
			g_print (" (struct mapi_SLPSTRArray *) (%d items)", lpProp->value.MVszA.cValues);
			for (j = 0; j < lpProp->value.MVszA.cValues; j++) {
				g_print ("\n      item[%d] = '%s'", j, lpProp->value.MVszA.strings[j].lppszA ? lpProp->value.MVszA.strings[j].lppszA : "[NULL]");
			}
			break;
		case PT_MV_SHORT:
			g_print (" PT_MV_SHORT");
			break;
		case PT_MV_LONG:
			g_print (" PT_MV_LONG");
			break;
		case PT_MV_FLOAT:
			g_print (" PT_MV_FLOAT");
			break;
		case PT_MV_DOUBLE:
			g_print (" PT_MV_DOUBLE");
			break;
		case PT_MV_CURRENCY:
			g_print (" PT_MV_CURRENCY");
			break;
		case PT_MV_APPTIME:
			g_print (" PT_MV_APPTIME");
			break;
		case PT_MV_I8:
			g_print (" PT_MV_I8");
			break;
		case PT_MV_UNICODE:
			g_print (" PT_MV_UNICODE (%d items)", lpProp->value.MVszW.cValues);
			for (j = 0; j < lpProp->value.MVszW.cValues; j++) {
				g_print ("\n      item[%d] = '%s'", j, lpProp->value.MVszW.strings[j].lppszW ? lpProp->value.MVszW.strings[j].lppszW : "[NULL]");
			}
			break;
		case PT_MV_SYSTIME:
			g_print (" PT_MV_SYSTIME");
			break;
		case PT_MV_CLSID:
			g_print (" PT_MV_CLSID");
			break;
		case PT_MV_BINARY:
			g_print (" PT_MV_BINARY (%d items)", lpProp->value.MVbin.cValues);
			for (j = 0; j < lpProp->value.MVbin.cValues; j++) {
				g_print ("\n      item[%d] (size %d)\n", j, lpProp->value.MVbin.bin[j].cb);
				dump_bin (lpProp->value.MVbin.bin[j].lpb, lpProp->value.MVbin.bin[j].cb, "        ");
			}
			break;
		default:
			g_print (" - Unknown type 0x%04X", lpProp->ulPropTag & 0xFFFF);
			break;
		}

		g_print ("\n");
	}
}

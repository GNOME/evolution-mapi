/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
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
 * Authors:
 *    Milan Crha <mcrha@redhat.com>
 *
 * Copyright (C) 2011 Red Hat, Inc. (www.redhat.com)
 *
 */

/* Array copied from OpenChange source, till it's available in OpenChange's API */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <libmapi/libmapi.h>
#include <libmapi/mapi_nameid.h>

#include "e-mapi-openchange.h"

static struct mapi_nameid_tags mapi_nameid_tags[] = {
{ PidLidAddressBookProviderArrayType                          , "ABPArrayType"                                                   , 0x8029, NULL, PT_LONG        , MNID_ID, PSETID_Address, 0x0 },
{ PidLidAddressBookProviderEmailList                          , "ABPEmailList"                                                   , 0x8028, NULL, PT_MV_LONG     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidAddressCountryCode                                    , "AddressCountryCode"                                             , 0x80dd, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidAnniversaryEventEntryId                               , "AnniversaryEventEID"                                            , 0x804e, NULL, PT_BINARY      , MNID_ID, PSETID_Address, 0x0 },
{ PidLidAutoLog                                               , "AutoLog"                                                        , 0x8025, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidBirthdayEventEntryId                                  , "BirthdayEventEID"                                               , 0x804d, NULL, PT_BINARY      , MNID_ID, PSETID_Address, 0x0 },
{ PidLidBirthdayLocal                                         , "ApptBirthdayLocal"                                              , 0x80de, NULL, PT_SYSTIME     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidBusinessCardCardPicture                               , "BCCardPicture"                                                  , 0x8041, NULL, PT_BINARY      , MNID_ID, PSETID_Address, 0x0 },
{ PidLidBusinessCardDisplayDefinition                         , "BCDisplayDefinition"                                            , 0x8040, NULL, PT_BINARY      , MNID_ID, PSETID_Address, 0x0 },
{ PidLidContactCharacterSet                                   , "ContactCharSet"                                                 , 0x8023, NULL, PT_LONG        , MNID_ID, PSETID_Address, 0x0 },
{ PidLidContactItemData                                       , "ContactItemData"                                                , 0x8007, NULL, PT_MV_LONG     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidContactUserField1                                     , "ContactUserField1"                                              , 0x804f, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidContactUserField2                                     , "ContactUserField2"                                              , 0x8050, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidContactUserField3                                     , "ContactUserField3"                                              , 0x8051, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidContactUserField4                                     , "ContactUserField4"                                              , 0x8052, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidDepartment                                            , "Department"                                                     , 0x8010, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidDistributionListChecksum                              , "DLChecksum"                                                     , 0x804c, NULL, PT_LONG        , MNID_ID, PSETID_Address, 0x0 },
{ PidLidDistributionListMembers                               , "DLMembers"                                                      , 0x8055, NULL, PT_MV_BINARY   , MNID_ID, PSETID_Address, 0x0 },
{ PidLidDistributionListName                                  , "DLName"                                                         , 0x8053, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidDistributionListOneOffMembers                         , "DLOneOffMembers"                                                , 0x8054, NULL, PT_MV_BINARY   , MNID_ID, PSETID_Address, 0x0 },
{ PidLidDistributionListStream                                , "DLStream"                                                       , 0x8064, NULL, PT_BINARY      , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail1AddressType                                     , "Email1AddrType"                                                 , 0x8082, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail1DisplayName                                     , "Email1DisplayName"                                              , 0x8080, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail1EmailAddress                                    , "Email1EmailAddress"                                             , 0x8083, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail1OriginalDisplayName                             , "Email1OriginalDisplayName"                                      , 0x8084, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail1OriginalEntryId                                 , "Email1OriginalEntryID"                                          , 0x8085, NULL, PT_BINARY      , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail1RichTextFormat                                  , "Email1RTF"                                                      , 0x8086, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail2AddressType                                     , "Email2AddrType"                                                 , 0x8092, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail2DisplayName                                     , "Email2DisplayName"                                              , 0x8090, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail2EmailAddress                                    , "Email2EmailAddress"                                             , 0x8093, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail2OriginalDisplayName                             , "Email2OriginalDisplayName"                                      , 0x8094, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail2OriginalEntryId                                 , "Email2OriginalEntryID"                                          , 0x8095, NULL, PT_BINARY      , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail2RichTextFormat                                  , "Email1RTF"                                                      , 0x8096, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail3AddressType                                     , "Email3AddrType"                                                 , 0x80a2, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail3DisplayName                                     , "Email3DisplayName"                                              , 0x80a0, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail3EmailAddress                                    , "Email3EmailAddress"                                             , 0x80a3, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail3OriginalDisplayName                             , "Email3OriginalDisplayName"                                      , 0x80a4, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail3OriginalEntryId                                 , "Email3OriginalEntryID"                                          , 0x80a5, NULL, PT_BINARY      , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmail3RichTextFormat                                  , "Email1RTF"                                                      , 0x80a6, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidEmailList                                             , "EmailList"                                                      , 0x8027, NULL, PT_MV_LONG     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFax1AddressType                                       , "Fax1AddrType"                                                   , 0x80b2, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFax1EmailAddress                                      , "Fax1EmailAddress"                                               , 0x80b3, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFax1OriginalDisplayName                               , "Fax1OriginalDisplayName"                                        , 0x80b4, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFax1OriginalEntryId                                   , "Fax1OriginalEntryID"                                            , 0x80b5, NULL, PT_BINARY      , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFax2AddressType                                       , "Fax2AddrType"                                                   , 0x80c2, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFax2EmailAddress                                      , "Fax2EmailAddress"                                               , 0x80c3, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFax2OriginalDisplayName                               , "Fax2OriginalDisplayName"                                        , 0x80c4, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFax2OriginalEntryId                                   , "Fax2OriginalEntryID"                                            , 0x80c5, NULL, PT_BINARY      , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFax3AddressType                                       , "Fax3AddrType"                                                   , 0x80d2, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFax3EmailAddress                                      , "Fax3EmailAddress"                                               , 0x80d3, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFax3OriginalDisplayName                               , "Fax3OriginalDisplayName"                                        , 0x80d4, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFax3OriginalEntryId                                   , "Fax3OriginalEntryID"                                            , 0x80d5, NULL, PT_BINARY      , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFileUnder                                             , "FileUnder"                                                      , 0x8005, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFileUnderId                                           , "FileUnderId"                                                    , 0x8006, NULL, PT_LONG        , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFileUnderList                                         , "FileUnderList"                                                  , 0x8026, NULL, PT_MV_LONG     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidFreeBusyLocation                                      , "FreeBusyLocation"                                               , 0x80d8, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidHasPicture                                            , "HasPicture"                                                     , 0x8015, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidHomeAddress                                           , "HomeAddress"                                                    , 0x801a, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidHomeAddressCountryCode                                , "HomeAddressCountryCode"                                         , 0x80da, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidHtml                                                  , "HTML"                                                           , 0x802b, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidInstantMessagingAddress                               , "InstMsg"                                                        , 0x8062, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidOtherAddress                                          , "OtherAddress"                                                   , 0x801c, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidOtherAddressCountryCode                               , "OtherAddressCountryCode"                                        , 0x80dc, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidPostalAddressId                                       , "PostalAddressId"                                                , 0x8022, NULL, PT_LONG        , MNID_ID, PSETID_Address, 0x0 },
{ PidLidReferredBy                                            , "ReferredBy"                                                     , 0x800e, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidWeddingAnniversaryLocal                               , "ApptAnniversaryLocal"                                           , 0x80df, NULL, PT_SYSTIME     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidWorkAddress                                           , "WorkAddress"                                                    , 0x801b, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidWorkAddressCity                                       , "WorkAddressCity"                                                , 0x8046, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidWorkAddressCountry                                    , "WorkAddressCountry"                                             , 0x8049, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidWorkAddressCountryCode                                , "WorkAddressCountryCode"                                         , 0x80db, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidWorkAddressPostalCode                                 , "WorkAddressPostalCode"                                          , 0x8048, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidWorkAddressPostOfficeBox                              , "WorkAddressPostOfficeBox"                                       , 0x804a, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidWorkAddressState                                      , "WorkAddressState"                                               , 0x8047, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidYomiCompanyName                                       , "YomiCompanyName"                                                , 0x802e, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidYomiFirstName                                         , "YomiFirstName"                                                  , 0x802c, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidYomiLastName                                          , "YomiLastName"                                                   , 0x802d, NULL, PT_UNICODE     , MNID_ID, PSETID_Address, 0x0 },
{ PidLidAllAttendeesString                                    , "AllAttendeesString"                                             , 0x8238, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAllowExternalCheck                                    , "AllowExternCheck"                                               , 0x8246, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentAuxiliaryFlags                             , "ApptAuxFlags"                                                   , 0x8207, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentColor                                      , "ApptColor"                                                      , 0x8214, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentCounterProposal                            , "ApptCounterProposal"                                            , 0x8257, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentDuration                                   , "ApptDuration"                                                   , 0x8213, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentEndDate                                    , "ApptEndDate"                                                    , 0x8211, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentEndTime                                    , "ApptEndTime"                                                    , 0x8210, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentEndWhole                                   , "ApptEndWhole"                                                   , 0x820e, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentLastSequence                               , "ApptLastSequence"                                               , 0x8203, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentNotAllowPropose                            , "ApptNotAllowPropose"                                            , 0x825a, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentProposalNumber                             , "ApptProposalNum"                                                , 0x8259, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentProposedDuration                           , "ApptProposedDuration"                                           , 0x8256, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentProposedEndWhole                           , "ApptProposedEndWhole"                                           , 0x8251, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentProposedStartWhole                         , "ApptProposedStartWhole"                                         , 0x8250, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentRecur                                      , "ApptRecur"                                                      , 0x8216, NULL, PT_BINARY      , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentReplyName                                  , "ApptReplyName, http://schemas.microsoft.com/mapi/apptreplyname" , 0x8230, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentReplyTime                                  , "ApptReplyTime"                                                  , 0x8220, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentSequence                                   , "ApptSequence"                                                   , 0x8201, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentSequenceTime                               , "ApptSeqTime"                                                    , 0x8202, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentStartDate                                  , "ApptStartDate"                                                  , 0x8212, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentStartTime                                  , "ApptStartTime"                                                  , 0x820f, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentStartWhole                                 , "ApptStartWhole"                                                 , 0x820d, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentStateFlags                                 , "ApptStateFlags"                                                 , 0x8217, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentSubType                                    , "ApptSubType"                                                    , 0x8215, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentTimeZoneDefinitionEndDisplay               , "ApptTZDefEndDisplay"                                            , 0x825f, NULL, PT_BINARY      , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentTimeZoneDefinitionRecur                    , "ApptTZDefRecur"                                                 , 0x8260, NULL, PT_BINARY      , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentTimeZoneDefinitionStartDisplay             , "ApptTZDefStartDisplay"                                          , 0x825e, NULL, PT_BINARY      , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentUnsendableRecipients                       , "ApptUnsendableRecips"                                           , 0x825d, NULL, PT_BINARY      , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAppointmentUpdateTime                                 , "ApptUpdateTime"                                                 , 0x8226, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAutoFillLocation                                      , "AutoFillLocation"                                               , 0x823a, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidAutoStartCheck                                        , "AutoStartCheck"                                                 , 0x8244, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidBusyStatus                                            , "BusyStatus"                                                     , 0x8205, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidCcAttendeesString                                     , "CCAttendeesString"                                              , 0x823c, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidChangeHighlight                                       , "ChangeHighlight"                                                , 0x8204, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidClipEnd                                               , "ClipEnd"                                                        , 0x8236, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidClipStart                                             , "ClipStart"                                                      , 0x8235, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidCollaborateDoc                                        , "CollaborateDoc"                                                 , 0x8247, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidConferencingCheck                                     , "ConfCheck"                                                      , 0x8240, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidConferencingType                                      , "ConfType"                                                       , 0x8241, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidDirectory                                             , "Directory"                                                      , 0x8242, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidExceptionReplaceTime                                  , "ExceptionReplaceTime"                                           , 0x8228, NULL, PT_SYSTIME     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidFExceptionalAttendees                                 , "FExceptionalAttendees"                                          , 0x822b, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidFExceptionalBody                                      , "FExceptionalBody"                                               , 0x8206, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidFInvited                                              , "FInvited"                                                       , 0x8229, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidForwardInstance                                       , "FwrdInstance"                                                   , 0x820a, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidForwardNotificationRecipients                         , "ForwardNotificationRecipients"                                  , 0x8261, NULL, PT_BINARY      , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidFOthersAppointment                                    , "FOthersAppt, http://schemas.microsoft.com/mapi/fothersappt"     , 0x822f, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidInboundICalStream                                     , "InboundICalStream, dispidInboundICalStream"                     , 0x827a, NULL, PT_BINARY      , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidIntendedBusyStatus                                    , "IntendedBusyStatus"                                             , 0x8224, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidLinkedTaskItems                                       , "LinkedTaskItems"                                                , 0x820c, NULL, PT_MV_BINARY   , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidLocation                                              , "Location"                                                       , 0x8208, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidMeetingWorkspaceUrl                                   , "MWSURL"                                                         , 0x8209, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidNetShowUrl                                            , "NetShowURL"                                                     , 0x8248, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidOnlinePassword                                        , "OnlinePassword"                                                 , 0x8249, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidOrganizerAlias                                        , "OrgAlias"                                                       , 0x8243, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidOriginalStoreEntryId                                  , "OrigStoreEid, http://schemas.microsoft.com/mapi/origstoreeid"   , 0x8237, NULL, PT_BINARY      , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidOwnerName                                             , "OwnerName"                                                      , 0x822e, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidRecurrencePattern                                     , "RecurPattern"                                                   , 0x8232, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidRecurrenceType                                        , "RecurType"                                                      , 0x8231, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidRecurring                                             , "Recurring"                                                      , 0x8223, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidResponseStatus                                        , "ResponseStatus"                                                 , 0x8218, NULL, PT_LONG        , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidSingleBodyICal                                        , "IsSingleBodyICal, dispidIsSingleBodyICal"                       , 0x827b, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidTimeZoneDescription                                   , "TimeZoneDesc"                                                   , 0x8234, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidTimeZoneStruct                                        , "TimeZoneStruct"                                                 , 0x8233, NULL, PT_BINARY      , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidToAttendeesString                                     , "ToAttendeesString"                                              , 0x823b, NULL, PT_UNICODE     , MNID_ID, PSETID_Appointment, 0x0 },
{ PidLidClientIntent                                          , "ClientIntent"                                                   , 0x0015, NULL, PT_LONG        , MNID_ID, PSETID_CalendarAssistant, 0x0 },
{ PidLidServerProcessed                                       , "ExchangeProcessed"                                              , 0x85cc, NULL, PT_BOOLEAN     , MNID_ID, PSETID_CalendarAssistant, 0x0 },
{ PidLidServerProcessingActions                               , "ExchangeProcessingAction"                                       , 0x85cd, NULL, PT_LONG        , MNID_ID, PSETID_CalendarAssistant, 0x0 },
{ PidLidAgingDontAgeMe                                        , "AgingDontAgeMe"                                                 , 0x850e, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidAutoProcessState                                      , "SniffState"                                                     , 0x851a, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidBilling                                               , "Billing"                                                        , 0x8535, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidClassification                                        , "Classification"                                                 , 0x85b6, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidClassificationDescription                             , "ClassDesc"                                                      , 0x85b7, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidClassificationGuid                                    , "ClassGuid"                                                      , 0x85b8, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidClassificationKeep                                    , "ClassKeep"                                                      , 0x85ba, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidClassified                                            , "Classified"                                                     , 0x85b5, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidCommonEnd                                             , "CommonEnd"                                                      , 0x8517, NULL, PT_SYSTIME     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidCommonStart                                           , "CommonStart"                                                    , 0x8516, NULL, PT_SYSTIME     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidCompanies                                             , "Companies, http://schemas.microsoft.com/exchange/companies"     , 0x8539, NULL, PT_MV_UNICODE  , MNID_ID, PSETID_Common, 0x0 },
{ PidLidContactLinkEntry                                      , "ContactLinkEntry"                                               , 0x8585, NULL, PT_BINARY      , MNID_ID, PSETID_Common, 0x0 },
{ PidLidContactLinkName                                       , "ContactLinkName"                                                , 0x8586, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidContactLinkSearchKey                                  , "ContactLinkSearchKey"                                           , 0x8584, NULL, PT_BINARY      , MNID_ID, PSETID_Common, 0x0 },
{ PidLidContacts                                              , "Contacts"                                                       , 0x853a, NULL, PT_MV_UNICODE  , MNID_ID, PSETID_Common, 0x0 },
{ PidLidConversationActionLastAppliedTime                     , "ConvActionLastAppliedTime"                                      , 0x85ca, NULL, PT_SYSTIME     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidConversationActionMaxDeliveryTime                     , "ConvActionMaxDeliveryTime"                                      , 0x85c8, NULL, PT_SYSTIME     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidConversationActionMoveFolderEid                       , "ConvActionMoveFolderEid"                                        , 0x85c6, NULL, PT_BINARY      , MNID_ID, PSETID_Common, 0x0 },
{ PidLidConversationActionMoveStoreEid                        , "ConvActionMoveStoreEid"                                         , 0x85c7, NULL, PT_BINARY      , MNID_ID, PSETID_Common, 0x0 },
{ PidLidConversationActionVersion                             , "ConvActionVersion"                                              , 0x85cb, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidConversationProcessed                                 , "ConvExLegacyProcessedRand"                                      , 0x85c9, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidCurrentVersion                                        , "CurrentVersion"                                                 , 0x8552, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidCurrentVersionName                                    , "CurrentVersionName"                                             , 0x8554, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidDayOfMonth                                            , "NULL"                                                           , 0x1000, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidFlagRequest                                           , "Request"                                                        , 0x8530, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidFlagString                                            , "FlagStringEnum"                                                 , 0x85c0, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidICalendarDayOfWeekMask                                , "http://schemas.microsoft.com/mapi/dayofweekmask"                , 0x1001, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidInfoPathFormName                                      , "NULL"                                                           , 0x85b1, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidInternetAccountName                                   , "InetAcctName"                                                   , 0x8580, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidInternetAccountStamp                                  , "InetAcctStamp"                                                  , 0x8581, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidMonthOfYear                                           , "NULL"                                                           , 0x1006, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidNoEndDateFlag                                         , "http://schemas.microsoft.com/mapi/fnoenddate"                   , 0x100b, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidNonSendableBcc                                        , "NonSendableBCC"                                                 , 0x8538, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidNonSendableCc                                         , "NonSendableCC"                                                  , 0x8537, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidNonSendableTo                                         , "NonSendableTo"                                                  , 0x8536, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidNonSendBccTrackStatus                                 , "NonSendBccTrackStatus"                                          , 0x8545, NULL, PT_MV_LONG     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidNonSendCcTrackStatus                                  , "NonSendCcTrackStatus"                                           , 0x8544, NULL, PT_MV_LONG     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidNonSendToTrackStatus                                  , "NonSendToTrackStatus"                                           , 0x8543, NULL, PT_MV_LONG     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidOccurrences                                           , "NULL"                                                           , 0x1005, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidPrivate                                               , "Private"                                                        , 0x8506, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidPromptSendUpdate                                      , "PromptSendUpdate"                                               , 0x8045, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidRecurrenceDuration                                    , "NULL"                                                           , 0x100d, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidReferenceEntryId                                      , "ReferenceEID"                                                   , 0x85bd, NULL, PT_BINARY      , MNID_ID, PSETID_Common, 0x0 },
{ PidLidReminderDelta                                         , "ReminderDelta, http://schemas.microsoft.com/mapi/reminderdelta" , 0x8501, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidReminderFileParameter                                 , "ReminderFileParam"                                              , 0x851f, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidReminderOverride                                      , "ReminderOverride"                                               , 0x851c, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidReminderPlaySound                                     , "ReminderPlaySound"                                              , 0x851e, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidReminderSet                                           , "ReminderSet"                                                    , 0x8503, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidReminderSignalTime                                    , "ReminderNextTime"                                               , 0x8560, NULL, PT_SYSTIME     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidReminderTime                                          , "ReminderTime"                                                   , 0x8502, NULL, PT_SYSTIME     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidReminderTimeDate                                      , "ReminderTimeDate"                                               , 0x8505, NULL, PT_SYSTIME     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidReminderTimeTime                                      , "ReminderTimeTime"                                               , 0x8504, NULL, PT_SYSTIME     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidReminderType                                          , "ReminderType, http://schemas.microsoft.com/mapi/remindertype"   , 0x851d, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidRemoteStatus                                          , "RemoteStatus"                                                   , 0x8511, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidSideEffects                                           , "SideEffects"                                                    , 0x8510, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidSmartNoAttach                                         , "SmartNoAttach"                                                  , 0x8514, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidSpamOriginalFolder                                    , "SpamOriginalFolder"                                             , 0x859c, NULL, PT_BINARY      , MNID_ID, PSETID_Common, 0x0 },
{ PidLidTaskGlobalId                                          , "TaskGlobalObjId"                                                , 0x8519, NULL, PT_BINARY      , MNID_ID, PSETID_Common, 0x0 },
{ PidLidTaskMode                                              , "TaskMode"                                                       , 0x8518, NULL, PT_LONG        , MNID_ID, PSETID_Common, 0x0 },
{ PidLidToDoOrdinalDate                                       , "ToDoOrdinalDate"                                                , 0x85a0, NULL, PT_SYSTIME     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidToDoSubOrdinal                                        , "ToDoSubOrdinal"                                                 , 0x85a1, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidToDoTitle                                             , "ToDoTitle"                                                      , 0x85a4, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidUseTnef                                               , "UseTNEF"                                                        , 0x8582, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidValidFlagStringProof                                  , "ValidFlagStringProof"                                           , 0x85bf, NULL, PT_SYSTIME     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidVerbResponse                                          , "VerbResponse"                                                   , 0x8524, NULL, PT_UNICODE     , MNID_ID, PSETID_Common, 0x0 },
{ PidLidVerbStream                                            , "VerbStream"                                                     , 0x8520, NULL, PT_BINARY      , MNID_ID, PSETID_Common, 0x0 },
{ PidLidLogDocumentPosted                                     , "LogDocPosted"                                                   , 0x8711, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Log, 0x0 },
{ PidLidLogDocumentPrinted                                    , "LogDocPrinted"                                                  , 0x870e, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Log, 0x0 },
{ PidLidLogDocumentRouted                                     , "LogDocRouted"                                                   , 0x8710, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Log, 0x0 },
{ PidLidLogDocumentSaved                                      , "LogDocSaved"                                                    , 0x870f, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Log, 0x0 },
{ PidLidLogDuration                                           , "LogDuration"                                                    , 0x8707, NULL, PT_LONG        , MNID_ID, PSETID_Log, 0x0 },
{ PidLidLogEnd                                                , "LogEnd"                                                         , 0x8708, NULL, PT_SYSTIME     , MNID_ID, PSETID_Log, 0x0 },
{ PidLidLogFlags                                              , "LogFlags"                                                       , 0x870c, NULL, PT_LONG        , MNID_ID, PSETID_Log, 0x0 },
{ PidLidLogStart                                              , "LogStart"                                                       , 0x8706, NULL, PT_SYSTIME     , MNID_ID, PSETID_Log, 0x0 },
{ PidLidLogType                                               , "LogType"                                                        , 0x8700, NULL, PT_UNICODE     , MNID_ID, PSETID_Log, 0x0 },
{ PidLidLogTypeDesc                                           , "LogTypeDesc"                                                    , 0x8712, NULL, PT_UNICODE     , MNID_ID, PSETID_Log, 0x0 },
{ PidLidAppointmentMessageClass                               , "ApptMessageClass"                                               , 0x0024, NULL, PT_UNICODE     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidAttendeeCriticalChange                                , "LID_ATTENDEE_CRITICAL_CHANGE"                                   , 0x0001, NULL, PT_SYSTIME     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidCalendarType                                          , "LID_CALENDAR_TYPE"                                              , 0x001c, NULL, PT_LONG        , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidCleanGlobalObjectId                                   , "CleanGlobalObjId"                                               , 0x0023, NULL, PT_BINARY      , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidDayInterval                                           , "LID_DAY_INTERVAL"                                               , 0x0011, NULL, PT_SHORT       , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidDelegateMail                                          , "LID_DELEGATE_MAIL"                                              , 0x0009, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidEndRecurrenceDate                                     , "LID_END_RECUR_DATE"                                             , 0x000f, NULL, PT_LONG        , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidEndRecurrenceTime                                     , "LID_END_RECUR_TIME"                                             , 0x0010, NULL, PT_LONG        , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidGlobalObjectId                                        , "LID_GLOBAL_OBJID"                                               , 0x0003, NULL, PT_BINARY      , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidIsException                                           , "LID_IS_EXCEPTION"                                               , 0x000a, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidIsRecurring                                           , "LID_IS_RECURRING"                                               , 0x0005, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidIsSilent                                              , "LID_IS_SILENT"                                                  , 0x0004, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidMeetingType                                           , "MeetingType"                                                    , 0x0026, NULL, PT_LONG        , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidMonthInterval                                         , "LID_MONTH_INTERVAL"                                             , 0x0013, NULL, PT_SHORT       , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidMonthOfYearMask                                       , "LID_MOY_MASK"                                                   , 0x0017, NULL, PT_LONG        , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidOldLocation                                           , "OldLocation"                                                    , 0x0028, NULL, PT_UNICODE     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidOldRecurrenceType                                     , "LID_RECUR_TYPE"                                                 , 0x0018, NULL, PT_SHORT       , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidOldWhenEndWhole                                       , "OldWhenEndWhole"                                                , 0x002a, NULL, PT_SYSTIME     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidOldWhenStartWhole                                     , "OldWhenStartWhole"                                              , 0x0029, NULL, PT_SYSTIME     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidOptionalAttendees                                     , "LID_OPTIONAL_ATTENDEES"                                         , 0x0007, NULL, PT_UNICODE     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidOwnerCriticalChange                                   , "LID_OWNER_CRITICAL_CHANGE"                                      , 0x001a, NULL, PT_SYSTIME     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidRequiredAttendees                                     , "LID_REQUIRED_ATTENDEES"                                         , 0x0006, NULL, PT_UNICODE     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidResourceAttendees                                     , "LID_RESOURCE_ATTENDEES"                                         , 0x0008, NULL, PT_UNICODE     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidStartRecurrenceDate                                   , "LID_START_RECUR_DATE"                                           , 0x000d, NULL, PT_LONG        , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidStartRecurrenceTime                                   , "LID_START_RECUR_TIME"                                           , 0x000e, NULL, PT_LONG        , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidTimeZone                                              , "LID_TIME_ZONE"                                                  , 0x000c, NULL, PT_LONG        , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidWeekInterval                                          , "LID_WEEK_INTERVAL"                                              , 0x0012, NULL, PT_SHORT       , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidWhere                                                 , "LID_WHERE"                                                      , 0x0002, NULL, PT_UNICODE     , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidYearInterval                                          , "LID_YEAR_INTERVAL"                                              , 0x0014, NULL, PT_SHORT       , MNID_ID, PSETID_Meeting, 0x0 },
{ PidLidNoteColor                                             , "NoteColor"                                                      , 0x8b00, NULL, PT_LONG        , MNID_ID, PSETID_Note, 0x0 },
{ PidLidNoteHeight                                            , "NoteHeight"                                                     , 0x8b03, NULL, PT_LONG        , MNID_ID, PSETID_Note, 0x0 },
{ PidLidNoteWidth                                             , "NoteWidth"                                                      , 0x8b02, NULL, PT_LONG        , MNID_ID, PSETID_Note, 0x0 },
{ PidLidNoteX                                                 , "NoteX"                                                          , 0x8b04, NULL, PT_LONG        , MNID_ID, PSETID_Note, 0x0 },
{ PidLidNoteY                                                 , "NoteY"                                                          , 0x8b05, NULL, PT_LONG        , MNID_ID, PSETID_Note, 0x0 },
{ PidLidPostRssChannel                                        , "PostRssChannel"                                                 , 0x8904, NULL, PT_UNICODE     , MNID_ID, PSETID_PostRss, 0x0 },
{ PidLidPostRssChannelLink                                    , "PostRssChannelLink"                                             , 0x8900, NULL, PT_UNICODE     , MNID_ID, PSETID_PostRss, 0x0 },
{ PidLidPostRssItemGuid                                       , "PostRssItemGuid"                                                , 0x8903, NULL, PT_UNICODE     , MNID_ID, PSETID_PostRss, 0x0 },
{ PidLidPostRssItemHash                                       , "PostRssItemHash"                                                , 0x8902, NULL, PT_LONG        , MNID_ID, PSETID_PostRss, 0x0 },
{ PidLidPostRssItemLink                                       , "PostRssItemLink"                                                , 0x8901, NULL, PT_UNICODE     , MNID_ID, PSETID_PostRss, 0x0 },
{ PidLidPostRssItemXml                                        , "PostRssItemXml"                                                 , 0x8905, NULL, PT_UNICODE     , MNID_ID, PSETID_PostRss, 0x0 },
{ PidLidPostRssSubscription                                   , "PostRssSubscription"                                            , 0x8906, NULL, PT_UNICODE     , MNID_ID, PSETID_PostRss, 0x0 },
{ PidLidSharingAnonymity                                      , "SharingAnonymity"                                               , 0x8a19, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingBindingEntryId                                 , "SharingBindingEid"                                              , 0x8a2d, NULL, PT_BINARY      , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingBrowseUrl                                      , "SharingBrowseUrl"                                               , 0x8a51, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingCapabilities                                   , "SharingCaps"                                                    , 0x8a17, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingConfigurationUrl                               , "SharingConfigUrl"                                               , 0x8a24, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingDataRangeEnd                                   , "SharingDataRangeEnd"                                            , 0x8a45, NULL, PT_SYSTIME     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingDataRangeStart                                 , "SharingDataRangeStart"                                          , 0x8a44, NULL, PT_SYSTIME     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingDetail                                         , "SharingDetail"                                                  , 0x8a2b, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingExtensionXml                                   , "SharingExtXml"                                                  , 0x8a21, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingFilter                                         , "SharingFilter"                                                  , 0x8a13, NULL, PT_BINARY      , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingFlags                                          , "SharingFlags"                                                   , 0x8a0a, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingFlavor                                         , "SharingFlavor"                                                  , 0x8a18, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingFolderEntryId                                  , "SharingFolderEid"                                               , 0x8a15, NULL, PT_BINARY      , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingIndexEntryId                                   , "SharingIndexEid"                                                , 0x8a2e, NULL, PT_BINARY      , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingInitiatorEntryId                               , "SharingInitiatorEid"                                            , 0x8a09, NULL, PT_BINARY      , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingInitiatorName                                  , "SharingInitiatorName"                                           , 0x8a07, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingInitiatorSmtp                                  , "SharingInitiatorSmtp"                                           , 0x8a08, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingInstanceGuid                                   , "SharingInstanceGuid"                                            , 0x8a1c, NULL, PT_BINARY      , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingLastAutoSyncTime                               , "SharingLastAutoSync"                                            , 0x8a55, NULL, PT_SYSTIME     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingLastSyncTime                                   , "SharingLastSync"                                                , 0x8a1f, NULL, PT_SYSTIME     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingLocalComment                                   , "SharingLocalComment"                                            , 0x8a4d, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingLocalLastModificationTime                      , "SharingLocalLastMod"                                            , 0x8a23, NULL, PT_SYSTIME     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingLocalName                                      , "SharingLocalName"                                               , 0x8a0f, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingLocalPath                                      , "SharingLocalPath"                                               , 0x8a0e, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingLocalStoreUid                                  , "SharingLocalStoreUid"                                           , 0x8a49, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingLocalType                                      , "SharingLocalType"                                               , 0x8a14, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingLocalUid                                       , "SharingLocalUid"                                                , 0x8a10, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingOriginalMessageEntryId                         , "SharingOriginalMessageEid"                                      , 0x8a29, NULL, PT_BINARY      , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingParentBindingEntryId                           , "SharingParentBindingEid"                                        , 0x8a5c, NULL, PT_BINARY      , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingParticipants                                   , "SharingParticipants"                                            , 0x8a1e, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingPermissions                                    , "SharingPermissions"                                             , 0x8a1b, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingProviderExtension                              , "SharingProviderExtension"                                       , 0x8a0b, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingProviderGuid                                   , "SharingProviderGuid"                                            , 0x8a01, NULL, PT_BINARY      , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingProviderName                                   , "SharingProviderName"                                            , 0x8a02, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingProviderUrl                                    , "SharingProviderUrl"                                             , 0x8a03, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRangeEnd                                       , "SharingRangeEnd"                                                , 0x8a47, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRangeStart                                     , "SharingRangeStart"                                              , 0x8a46, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingReciprocation                                  , "SharingReciprocation"                                           , 0x8a1a, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemoteByteSize                                 , "SharingRemoteByteSize"                                          , 0x8a4b, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemoteComment                                  , "SharingRemoteComment"                                           , 0x8a2f, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemoteCrc                                      , "SharingRemoteCrc"                                               , 0x8a4c, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemoteLastModificationTime                     , "SharingRemoteLastMod"                                           , 0x8a22, NULL, PT_SYSTIME     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemoteMessageCount                             , "SharingRemoteMsgCount"                                          , 0x8a4f, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemoteName                                     , "SharingRemoteName"                                              , 0x8a05, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemotePass                                     , "SharingRemotePass"                                              , 0x8a0d, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemotePath                                     , "SharingRemotePath"                                              , 0x8a04, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemoteStoreUid                                 , "SharingRemoteStoreUid"                                          , 0x8a48, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemoteType                                     , "SharingRemoteType"                                              , 0x8a1d, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemoteUid                                      , "SharingRemoteUid"                                               , 0x8a06, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemoteUser                                     , "SharingRemoteUser"                                              , 0x8a0c, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRemoteVersion                                  , "SharingRemoteVersion"                                           , 0x8a5b, NULL, PT_UNICODE     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingResponseTime                                   , "SharingResponseTime"                                            , 0x8a28, NULL, PT_SYSTIME     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingResponseType                                   , "SharingResponseType"                                            , 0x8a27, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingRoamLog                                        , "SharingRoamLog"                                                 , 0x8a4e, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingStart                                          , "SharingStart"                                                   , 0x8a25, NULL, PT_SYSTIME     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingStatus                                         , "SharingStatus"                                                  , 0x8a00, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingStop                                           , "SharingStop"                                                    , 0x8a26, NULL, PT_SYSTIME     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingSyncFlags                                      , "SharingSyncFlags"                                               , 0x8a60, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingSyncInterval                                   , "SharingSyncInterval"                                            , 0x8a2a, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingTimeToLive                                     , "SharingTimeToLive"                                              , 0x8a2c, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingTimeToLiveAuto                                 , "SharingTimeToLiveAuto"                                          , 0x8a56, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingWorkingHoursDays                               , "SharingWorkingHoursDays"                                        , 0x8a42, NULL, PT_LONG        , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingWorkingHoursEnd                                , "SharingWorkingHoursEnd"                                         , 0x8a41, NULL, PT_SYSTIME     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingWorkingHoursStart                              , "SharingWorkingHoursStart"                                       , 0x8a40, NULL, PT_SYSTIME     , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidSharingWorkingHoursTimeZone                           , "SharingWorkingHoursTZ"                                          , 0x8a43, NULL, PT_BINARY      , MNID_ID, PSETID_Sharing, 0x0 },
{ PidLidPercentComplete                                       , "PercentComplete"                                                , 0x8102, NULL, PT_DOUBLE      , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskAcceptanceState                                   , "TaskDelegValue"                                                 , 0x812a, NULL, PT_LONG        , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskAccepted                                          , "TaskAccepted"                                                   , 0x8108, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskActualEffort                                      , "TaskActualEffort"                                               , 0x8110, NULL, PT_LONG        , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskAssigner                                          , "TaskDelegator"                                                  , 0x8121, NULL, PT_UNICODE     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskAssigners                                         , "TaskMyDelegators"                                               , 0x8117, NULL, PT_BINARY      , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskComplete                                          , "TaskComplete"                                                   , 0x811c, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskCustomFlags                                       , "TaskActualEffort"                                               , 0x8139, NULL, PT_LONG        , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskDateCompleted                                     , "TaskDateCompleted"                                              , 0x810f, NULL, PT_SYSTIME     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskDeadOccurrence                                    , "TaskDeadOccur"                                                  , 0x8109, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskDueDate                                           , "TaskDueDate"                                                    , 0x8105, NULL, PT_SYSTIME     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskEstimatedEffort                                   , "TaskEstimatedEffort"                                            , 0x8111, NULL, PT_LONG        , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskFCreator                                          , "TaskFCreator"                                                   , 0x811e, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskFFixOffline                                       , "TaskFFixOffline"                                                , 0x812c, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskFRecurring                                        , "TaskFRecur"                                                     , 0x8126, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskHistory                                           , "TaskHistory"                                                    , 0x811a, NULL, PT_LONG        , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskLastDelegate                                      , "TaskLastDelegate"                                               , 0x8125, NULL, PT_UNICODE     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskLastUpdate                                        , "TaskLastUpdate"                                                 , 0x8115, NULL, PT_SYSTIME     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskLastUser                                          , "TaskLastUser"                                                   , 0x8122, NULL, PT_UNICODE     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskMultipleRecipients                                , "TaskMultRecips"                                                 , 0x8120, NULL, PT_LONG        , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskNoCompute                                         , "TaskNoCompute"                                                  , 0x8124, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskOrdinal                                           , "TaskOrdinal"                                                    , 0x8123, NULL, PT_LONG        , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskOwner                                             , "TaskOwner"                                                      , 0x811f, NULL, PT_UNICODE     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskOwnership                                         , "TaskOwnership"                                                  , 0x8129, NULL, PT_LONG        , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskRecurrence                                        , "TaskRecur"                                                      , 0x8116, NULL, PT_BINARY      , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskResetReminder                                     , "TaskResetReminder"                                              , 0x8107, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskRole                                              , "TaskRole"                                                       , 0x8127, NULL, PT_UNICODE     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskStartDate                                         , "TaskStartDate"                                                  , 0x8104, NULL, PT_SYSTIME     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskState                                             , "TaskState"                                                      , 0x8113, NULL, PT_LONG        , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskStatus                                            , "TaskStatus"                                                     , 0x8101, NULL, PT_LONG        , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskStatusOnComplete                                  , "TaskSOC"                                                        , 0x8119, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskUpdates                                           , "TaskUpdates"                                                    , 0x811b, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTaskVersion                                           , "TaskVersion"                                                    , 0x8112, NULL, PT_LONG        , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTeamTask                                              , "TeamTask"                                                       , 0x8103, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidTrustRecipientHighlights                              , "TrustRecipHighlights"                                           , 0x823e, NULL, PT_BOOLEAN     , MNID_ID, PSETID_Task, 0x0 },
{ PidLidCategories                                            , "Categories"                                                     , 0x9000, NULL, PT_MV_UNICODE  , MNID_ID, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameInstantMessagingAddress2                             , NULL                                                             , 0x0000, "IMAddress2", PT_UNICODE     , MNID_STRING, PSETID_AirSync, 0x0 },
{ PidNameInstantMessagingAddress3                             , NULL                                                             , 0x0000, "IMAddress3", PT_UNICODE     , MNID_STRING, PSETID_AirSync, 0x0 },
{ PidNameAttachmentMacContentType                             , NULL                                                             , 0x0000, "AttachmentMacContentType", PT_UNICODE     , MNID_STRING, PSETID_Attachment, 0x0 },
{ PidNameAttachmentMacInfo                                    , NULL                                                             , 0x0000, "AttachmentMacInfo", PT_BINARY      , MNID_STRING, PSETID_Attachment, 0x0 },
{ PidNameOriginalSpamConfidenceLevel                          , NULL                                                             , 0x0000, "OriginalScl", PT_LONG        , MNID_STRING, PSETID_Messaging, 0x0 },
{ PidNameAudioNotes                                           , NULL                                                             , 0x0000, "UMAudioNotes", PT_UNICODE     , MNID_STRING, PSETID_UnifiedMessaging, 0x0 },
{ PidNameAutomaticSpeechRecognitionData                       , NULL                                                             , 0x0000, "AsrData", PT_BINARY      , MNID_STRING, PSETID_UnifiedMessaging, 0x0 },
{ PidNameOutlookProtectionRuleTimestamp                       , NULL                                                             , 0x0000, "X-MS-Exchange-Organization-Outlook-Protection-Rule-Config-Timestamp", PT_UNICODE     , MNID_STRING, PSETID_UnifiedMessaging, 0x0 },
{ PidNameXUnifiedMessagingPartnerAssignedId                   , NULL                                                             , 0x0000, "X-MS-Exchange-UM-PartnerAssignedID", PT_UNICODE     , MNID_STRING, PSETID_UnifiedMessaging, 0x0 },
{ PidNameXUnifiedMessagingPartnerContent                      , NULL                                                             , 0x0000, "X-MS-Exchange-UM-PartnerContent", PT_UNICODE     , MNID_STRING, PSETID_UnifiedMessaging, 0x0 },
{ PidNameXUnifiedMessagingPartnerContext                      , NULL                                                             , 0x0000, "X-MS-Exchange-UM-PartnerContext", PT_UNICODE     , MNID_STRING, PSETID_UnifiedMessaging, 0x0 },
{ PidNameXUnifiedMessagingPartnerStatus                       , NULL                                                             , 0x0000, "X-MS-Exchange-UM-PartnerStatus", PT_UNICODE     , MNID_STRING, PSETID_UnifiedMessaging, 0x0 },
{ PidNameAcceptLanguage                                       , NULL                                                             , 0x0000, "Accept-Language", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameApprovalAllowedDecisionMakers                        , NULL                                                             , 0x0000, "X-MS-Exchange-Organization-Approval-Allowed-Decision-Makers", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameApprovalRequestor                                    , NULL                                                             , 0x0000, "X-MS-Exchange-Organization-Approval-Requestor", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameApproved                                             , NULL                                                             , 0x0000, "Approved", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameAuthenticatedAs                                      , NULL                                                             , 0x0000, "X-MS-Exchange-Organization-AuthAs", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameAuthenticatedDomain                                  , NULL                                                             , 0x0000, "X-MS-Exchange-Organization-AuthDomain", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameAuthenticatedMechanism                               , NULL                                                             , 0x0000, "X-MS-Exchange-Organization-AuthMechanism", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameAuthenticatedSource                                  , NULL                                                             , 0x0000, "X-MS-Exchange-Organization-AuthSource", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameBcc                                                  , NULL                                                             , 0x0000, "Bcc", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameCc                                                   , NULL                                                             , 0x0000, "Cc", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameContentBase                                          , NULL                                                             , 0x0000, "Content-Base", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameContentClass                                         , NULL                                                             , 0x0000, "Content-Class", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameContentDisposition                                   , NULL                                                             , 0x0000, "Content-Disposition", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameContentID                                            , NULL                                                             , 0x0000, "Content-ID", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameContentLanguage                                      , NULL                                                             , 0x0000, "Content-Language", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameContentLocation                                      , NULL                                                             , 0x0000, "Content-Location", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameContentTransferEncoding                              , NULL                                                             , 0x0000, "Content-Transfer-Encoding", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameContentType                                          , NULL                                                             , 0x0000, "Content-Type", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameControl                                              , NULL                                                             , 0x0000, "Control", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameCrossReference                                       , NULL                                                             , 0x0000, "Xref", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameDisposition                                          , NULL                                                             , 0x0000, "Disposition", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameDispositionNotificationTo                            , NULL                                                             , 0x0000, "Disposition-Notification-To", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameDistribution                                         , NULL                                                             , 0x0000, "Distribution", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameExpires                                              , NULL                                                             , 0x0000, "Expires", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameExpiryDate                                           , NULL                                                             , 0x0000, "Expiry-Date", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameFollowupTo                                           , NULL                                                             , 0x0000, "Followup-To", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameFrom                                                 , NULL                                                             , 0x0000, "From", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameImportance                                           , NULL                                                             , 0x0000, "Importance", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameInReplyTo                                            , NULL                                                             , 0x0000, "In-Reply-To", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameInternetComment                                      , NULL                                                             , 0x0000, "Comment", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameInternetKeywords                                     , NULL                                                             , 0x0000, "Keywords", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameInternetSubject                                      , NULL                                                             , 0x0000, "Subject", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameLines                                                , NULL                                                             , 0x0000, "Lines", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameMessageId                                            , NULL                                                             , 0x0000, "Message-ID", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameMimeVersion                                          , NULL                                                             , 0x0000, "Mime-Version", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameNewsgroups                                           , NULL                                                             , 0x0000, "Newsgroups", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameNntpPostingHost                                      , NULL                                                             , 0x0000, "NNTP-Posting-Host", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameOrganization                                         , NULL                                                             , 0x0000, "Organization", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameOriginalRecipient                                    , NULL                                                             , 0x0000, "Original-Recipient", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameOutlookProtectionRuleOverridden                      , NULL                                                             , 0x0000, "X-MS-Exchange-Organization-Outlook-Protection-Rule-Overridden", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameOutlookProtectionRuleVersion                         , NULL                                                             , 0x0000, "X-MS-Exchange-Organization-Outlook-Protection-Rule-Addin-Version", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNamePath                                                 , NULL                                                             , 0x0000, "Path", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNamePostingVersion                                       , NULL                                                             , 0x0000, "Posting-Version", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNamePriority                                             , NULL                                                             , 0x0000, "Priority", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameReceived                                             , NULL                                                             , 0x0000, "Received", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameReferences                                           , NULL                                                             , 0x0000, "References", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameRelayVersion                                         , NULL                                                             , 0x0000, "Relay-Version", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameReplyBy                                              , NULL                                                             , 0x0000, "Reply-By", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameReplyTo                                              , NULL                                                             , 0x0000, "Reply-To", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameReturnPath                                           , NULL                                                             , 0x0000, "Return-Path", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameReturnReceiptTo                                      , NULL                                                             , 0x0000, "Return-Receipt-To", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameRightsProtectMessage                                 , NULL                                                             , 0x0000, "X-MS-Exchange-Organization-RightsProtectMessage", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameSender                                               , NULL                                                             , 0x0000, "Sender", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameSensitivity                                          , NULL                                                             , 0x0000, "Sensitivity", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameSummary                                              , NULL                                                             , 0x0000, "Summary", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameThreadIndex                                          , NULL                                                             , 0x0000, "Thread-Index", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameThreadTopic                                          , NULL                                                             , 0x0000, "Thread-Topic", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameTo                                                   , NULL                                                             , 0x0000, "To", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXCallId                                              , NULL                                                             , 0x0000, "X-CallID", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXFaxNumberOfPages                                    , NULL                                                             , 0x0000, "X-FaxNumberOfPages", PT_SHORT       , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXMailer                                              , NULL                                                             , 0x0000, "X-Mailer", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXMessageCompleted                                    , NULL                                                             , 0x0000, "X-Message-Completed", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXMessageFlag                                         , NULL                                                             , 0x0000, "X-Message-Flag", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXRequireProtectedPlayOnPhone                         , NULL                                                             , 0x0000, "X-RequireProtectedPlayOnPhone", PT_BOOLEAN     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSenderTelephoneNumber                               , NULL                                                             , 0x0000, "X-CallingTelephoneNumber", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingBrowseUrl                                    , NULL                                                             , 0x0000, "X-Sharing-Browse-Url", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingCapabilities                                 , NULL                                                             , 0x0000, "X-Sharing-Capabilities", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingConfigUrl                                    , NULL                                                             , 0x0000, "X-Sharing-Config-Url", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingExendedCaps                                  , NULL                                                             , 0x0000, "X-Sharing-Exended-Caps", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingFlavor                                       , NULL                                                             , 0x0000, "X-Sharing-Flavor", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingInstanceGuid                                 , NULL                                                             , 0x0000, "X-Sharing-Instance-Guid", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingLocalType                                    , NULL                                                             , 0x0000, "X-Sharing-Local-Type", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingProviderGuid                                 , NULL                                                             , 0x0000, "X-Sharing-Provider-Guid", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingProviderName                                 , NULL                                                             , 0x0000, "X-Sharing-Provider-Name", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingProviderUrl                                  , NULL                                                             , 0x0000, "X-Sharing-Provider-Url", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingRemoteName                                   , NULL                                                             , 0x0000, "X-Sharing-Remote-Name", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingRemotePath                                   , NULL                                                             , 0x0000, "X-Sharing-Remote-Path", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingRemoteStoreUid                               , NULL                                                             , 0x0000, "X-Sharing-Remote-Store-Uid", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingRemoteType                                   , NULL                                                             , 0x0000, "X-Sharing-Remote-Type", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXSharingRemoteUid                                    , NULL                                                             , 0x0000, "X-Sharing-Remote-Uid", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXUnsent                                              , NULL                                                             , 0x0000, "X-Unsent", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXVoiceMessageAttachmentOrder                         , NULL                                                             , 0x0000, "X-AttachmentOrder", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXVoiceMessageDuration                                , NULL                                                             , 0x0000, "X-VoiceMessageDuration", PT_SHORT       , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameXVoiceMessageSenderName                              , NULL                                                             , 0x0000, "X-VoiceMessageSenderName", PT_UNICODE     , MNID_STRING, PS_INTERNET_HEADERS, 0x0 },
{ PidNameApplicationName                                      , NULL                                                             , 0x0000, "AppName", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameAuthor                                               , NULL                                                             , 0x0000, "Author", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameByteCount                                            , NULL                                                             , 0x0000, "ByteCount", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarAttendeeRole                                 , NULL                                                             , 0x0000, "urn:schemas:calendar:attendeerole", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarBusystatus                                   , NULL                                                             , 0x0000, "urn:schemas:calendar:busystatus", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarContact                                      , NULL                                                             , 0x0000, "urn:schemas:calendar:contact", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarContactUrl                                   , NULL                                                             , 0x0000, "urn:schemas:calendar:contacturl", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarCreated                                      , NULL                                                             , 0x0000, "urn:schemas:calendar:created", PT_SYSTIME     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarDescriptionUrl                               , NULL                                                             , 0x0000, "urn:schemas:calendar:descriptionurl", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarDuration                                     , NULL                                                             , 0x0000, "urn:schemas:calendar:duration", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarExceptionDate                                , NULL                                                             , 0x0000, "urn:schemas:calendar:exdate", PT_MV_SYSTIME  , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarExceptionRule                                , NULL                                                             , 0x0000, "urn:schemas:calendar:exrule", PT_MV_UNICODE  , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarGeoLatitude                                  , NULL                                                             , 0x0000, "urn:schemas:calendar:geolatitude", PT_DOUBLE      , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarGeoLongitude                                 , NULL                                                             , 0x0000, "urn:schemas:calendar:geolongitude", PT_DOUBLE      , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarInstanceType                                 , NULL                                                             , 0x0000, "urn:schemas:calendar:instancetype", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarIsOrganizer                                  , NULL                                                             , 0x0000, "urn:schemas:calendar:isorganizer", PT_BOOLEAN     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarLastModified                                 , NULL                                                             , 0x0000, "urn:schemas:calendar:lastmodified", PT_SYSTIME     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarLocationUrl                                  , NULL                                                             , 0x0000, "urn:schemas:calendar:locationurl", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarMeetingStatus                                , NULL                                                             , 0x0000, "urn:schemas:calendar:meetingstatus", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarMethod                                       , NULL                                                             , 0x0000, "urn:schemas:calendar:method", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarProductId                                    , NULL                                                             , 0x0000, "urn:schemas:calendar:prodid", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarRecurrenceIdRange                            , NULL                                                             , 0x0000, "urn:schemas:calendar:recurrenceidrange", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarReminderOffset                               , NULL                                                             , 0x0000, "urn:schemas:calendar:reminderoffset", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarResources                                    , NULL                                                             , 0x0000, "urn:schemas:calendar:resources", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarRsvp                                         , NULL                                                             , 0x0000, "urn:schemas:calendar:rsvp", PT_BOOLEAN     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarSequence                                     , NULL                                                             , 0x0000, "urn:schemas:calendar:sequence", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarTimeZone                                     , NULL                                                             , 0x0000, "urn:schemas:calendar:timezone", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarTimeZoneId                                   , NULL                                                             , 0x0000, "urn:schemas:calendar:timezoneid", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarTransparent                                  , NULL                                                             , 0x0000, "urn:schemas:calendar:transparent", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarUid                                          , NULL                                                             , 0x0000, "urn:schemas:calendar:uid", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCalendarVersion                                      , NULL                                                             , 0x0000, "urn:schemas:calendar:version", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCategory                                             , NULL                                                             , 0x0000, "Category", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCharacterCount                                       , NULL                                                             , 0x0000, "CharCount", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameComments                                             , NULL                                                             , 0x0000, "Comments", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCompany                                              , NULL                                                             , 0x0000, "Company", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsAlternateRecipient                           , NULL                                                             , 0x0000, "urn:schemas:contacts:alternaterecipient", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsCountry                                      , NULL                                                             , 0x0000, "urn:schemas:contacts:c", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsEmail1                                       , NULL                                                             , 0x0000, "urn:schemas:contacts:email1", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsEmail2                                       , NULL                                                             , 0x0000, "urn:schemas:contacts:email2", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsEmail3                                       , NULL                                                             , 0x0000, "urn:schemas:contacts:email3", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsFileAs                                       , NULL                                                             , 0x0000, "urn:schemas:contacts:fileas", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsFileasId                                     , NULL                                                             , 0x0000, "urn:schemas:contacts:fileasid", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsHomeLatitude                                 , NULL                                                             , 0x0000, "urn:schemas:contacts:homelatitude", PT_DOUBLE      , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsHomeLongitude                                , NULL                                                             , 0x0000, "urn:schemas:contacts:homelongitude", PT_DOUBLE      , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsHomeTimeZone                                 , NULL                                                             , 0x0000, "urn:schemas:contacts:hometimezone", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsMapUrl                                       , NULL                                                             , 0x0000, "urn:schemas:contacts:mapurl", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsOtherCountryCode                             , NULL                                                             , 0x0000, "urn:schemas:contacts:othercountrycode", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsOtherPager                                   , NULL                                                             , 0x0000, "urn:schemas:contacts:otherpager", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsOtherTimeZone                                , NULL                                                             , 0x0000, "urn:schemas:contacts:othertimezone", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsProxyAddresses                               , NULL                                                             , 0x0000, "urn:schemas:contacts:proxyaddresses", PT_MV_UNICODE  , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsSecretaryUrl                                 , NULL                                                             , 0x0000, "urn:schemas:contacts:secretaryurl", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameContactsSourceUrl                                    , NULL                                                             , 0x0000, "urn:schemas:contacts:sourceurl", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameCreateDateTimeReadOnly                               , NULL                                                             , 0x0000, "CreateDtmRo", PT_SYSTIME     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameDavGetContentType                                    , NULL                                                             , 0x0000, "DAV:getcontenttype", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameDavId                                                , NULL                                                             , 0x0000, "DAV:id", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameDavIsCollection                                      , NULL                                                             , 0x0000, "DAV:iscollection", PT_BOOLEAN     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameDavIsStructuredDocument                              , NULL                                                             , 0x0000, "DAV:isstructureddocument", PT_BOOLEAN     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameDavParentName                                        , NULL                                                             , 0x0000, "DAV:parentname", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameDavResourceType                                      , NULL                                                             , 0x0000, "DAV:resourcetype", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameDavSearchRequest                                     , NULL                                                             , 0x0000, "DAV:searchrequest", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameDavSearchType                                        , NULL                                                             , 0x0000, "DAV:searchtype", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameDavUid                                               , NULL                                                             , 0x0000, "DAV:uid", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameDocumentParts                                        , NULL                                                             , 0x0000, "DocParts", PT_MV_UNICODE  , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameEditTime                                             , NULL                                                             , 0x0000, "EditTime", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameExchangeIntendedBusyStatus                           , NULL                                                             , 0x0000, "http://schemas.microsoft.com/exchange/intendedbusystatus", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameExchangeJunkEmailMoveStamp                           , NULL                                                             , 0x0000, "http://schemas.microsoft.com/exchange/junkemailmovestamp", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameExchangeModifyExceptionStructure                     , NULL                                                             , 0x0000, "http://schemas.microsoft.com/exchange/modifyexceptionstruct", PT_BINARY      , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameExchangeNoModifyExceptions                           , NULL                                                             , 0x0000, "http://schemas.microsoft.com/exchange/nomodifyexceptions", PT_BOOLEAN     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameExchangePatternEnd                                   , NULL                                                             , 0x0000, "http://schemas.microsoft.com/exchange/patternend", PT_SYSTIME     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameExchangePatternStart                                 , NULL                                                             , 0x0000, "http://schemas.microsoft.com/exchange/patternstart", PT_SYSTIME     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameExchangePublicFolderEmailAddress                     , NULL                                                             , 0x0000, "http://schemas.microsoft.com/exchange/publicfolderemailaddress", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameExchangeReminderInterval                             , NULL                                                             , 0x0000, "http://schemas.microsoft.com/exchange/reminderinterval", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameExchDatabaseSchema                                   , NULL                                                             , 0x0000, "urn:schemas-microsoft-com:exch-data:baseschema", PT_MV_UNICODE  , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameExchDataExpectedContentClass                         , NULL                                                             , 0x0000, "urn:schemas-microsoft-com:exch-data:expected-content-class", PT_MV_UNICODE  , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameExchDataSchemaCollectionReference                    , NULL                                                             , 0x0000, "urn:schemas-microsoft-com:exch-data:schema-collection-ref", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHeadingPairs                                         , NULL                                                             , 0x0000, "HeadingPairs", PT_BINARY      , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHiddenCount                                          , NULL                                                             , 0x0000, "HiddenCount", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHttpmailCalendar                                     , NULL                                                             , 0x0000, "urn:schemas:httpmail:calendar", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHttpmailCc                                           , NULL                                                             , 0x0000, "urn:schemas:httpmail:cc", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHttpmailContacts                                     , NULL                                                             , 0x0000, "urn:schemas:httpmail:contacts", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHttpmailContentMediaType                             , NULL                                                             , 0x0000, "urn:schemas:httpmail:content-media-type", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHttpmailFrom                                         , NULL                                                             , 0x0000, "urn:schemas:httpmail:from", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHttpmailFromEmail                                    , NULL                                                             , 0x0000, "urn:schemas:httpmail:fromemail", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHttpmailHtmlDescription                              , NULL                                                             , 0x0000, "urn:schemas:httpmail:htmldescription", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHttpmailOutbox                                       , NULL                                                             , 0x0000, "urn:schemas:httpmail:outbox", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHttpmailSendMessage                                  , NULL                                                             , 0x0000, "urn:schemas:httpmail:sendmsg", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHttpmailSubmitted                                    , NULL                                                             , 0x0000, "urn:schemas:httpmail:submitted", PT_BOOLEAN     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameHttpmailTo                                           , NULL                                                             , 0x0000, "urn:schemas:httpmail:to", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameICalendarRecurrenceDate                              , NULL                                                             , 0x0000, "urn:schemas:calendar:rdate", PT_MV_SYSTIME  , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameICalendarRecurrenceRule                              , NULL                                                             , 0x0000, "urn:schemas:calendar:rrule", PT_MV_UNICODE  , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameKeywords                                             , NULL                                                             , 0x0000, "Keywords", PT_MV_UNICODE  , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameLastAuthor                                           , NULL                                                             , 0x0000, "LastAuthor", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameLastPrinted                                          , NULL                                                             , 0x0000, "LastPrinted", PT_SYSTIME     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameLastSaveDateTime                                     , NULL                                                             , 0x0000, "LastSaveDtm", PT_SYSTIME     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameLineCount                                            , NULL                                                             , 0x0000, "LineCount", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameLinksDirty                                           , NULL                                                             , 0x0000, "LinksDirty", PT_BOOLEAN     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameMailSubmissionUri                                    , NULL                                                             , 0x0000, "MAIL:submissionuri", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameManager                                              , NULL                                                             , 0x0000, "Manager", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameMultimediaClipCount                                  , NULL                                                             , 0x0000, "MMClipCount", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameNoteCount                                            , NULL                                                             , 0x0000, "NoteCount", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameOMSAccountGuid                                       , NULL                                                             , 0x0000, "OMSAccountGuid", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameOMSMobileModel                                       , NULL                                                             , 0x0000, "OMSMobileModel", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameOMSScheduleTime                                      , NULL                                                             , 0x0000, "OMSScheduleTime", PT_SYSTIME     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameOMSServiceType                                       , NULL                                                             , 0x0000, "OMSServiceType", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameOMSSourceType                                        , NULL                                                             , 0x0000, "OMSSourceType", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNamePageCount                                            , NULL                                                             , 0x0000, "PageCount", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameParagraphCount                                       , NULL                                                             , 0x0000, "ParCount", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNamePhishingStamp                                        , NULL                                                             , 0x0000, "http://schemas.microsoft.com/outlook/phishingstamp", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNamePresentationFormat                                   , NULL                                                             , 0x0000, "PresFormat", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameQuarantineOriginalSender                             , NULL                                                             , 0x0000, "quarantine-original-sender", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameRevisionNumber                                       , NULL                                                             , 0x0000, "RevNumber", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameRightsManagementLicense                              , NULL                                                             , 0x0000, "DRMLicense", PT_MV_BINARY   , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameScale                                                , NULL                                                             , 0x0000, "Scale", PT_BOOLEAN     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameSecurity                                             , NULL                                                             , 0x0000, "Security", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameSlideCount                                           , NULL                                                             , 0x0000, "SlideCount", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameSubject                                              , NULL                                                             , 0x0000, "Subject", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameTemplate                                             , NULL                                                             , 0x0000, "Template", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameThumbnail                                            , NULL                                                             , 0x0000, "Thumbnail", PT_BINARY      , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameTitle                                                , NULL                                                             , 0x0000, "Title", PT_UNICODE     , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ PidNameWordCount                                            , NULL                                                             , 0x0000, "WordCount", PT_LONG        , MNID_STRING, PS_PUBLIC_STRINGS, 0x0 },
{ 0x00000000                                                  , NULL                                                             , 0x0000, NULL, PT_UNSPECIFIED , 0x0, NULL, 0x0 }
};

static void
set_errno (enum MAPISTATUS status)
{
	errno = status;
}

enum MAPISTATUS
e_mapi_nameid_lid_lookup_canonical (uint16_t lid, const char *OLEGUID, uint32_t *propTag)
{
	uint32_t	i;

	/* Sanity checks */
	OPENCHANGE_RETVAL_IF(!lid, MAPI_E_INVALID_PARAMETER, NULL);
	OPENCHANGE_RETVAL_IF(!OLEGUID, MAPI_E_INVALID_PARAMETER, NULL);
	OPENCHANGE_RETVAL_IF(!propTag, MAPI_E_INVALID_PARAMETER, NULL);

	for (i = 0; mapi_nameid_tags[i].OLEGUID; i++) {
		if (mapi_nameid_tags[i].lid == lid &&
		    !strcmp(mapi_nameid_tags[i].OLEGUID, OLEGUID)) {
			*propTag = mapi_nameid_tags[i].proptag;
			return MAPI_E_SUCCESS;
		}
	}

	OPENCHANGE_RETVAL_ERR(MAPI_E_NOT_FOUND, NULL);
}

enum MAPISTATUS
e_mapi_nameid_string_lookup_canonical(const char *Name, const char *OLEGUID, uint32_t *propTag)
{
	uint32_t	i;

	/* Sanity checks */
	OPENCHANGE_RETVAL_IF(!Name, MAPI_E_INVALID_PARAMETER, NULL);
	OPENCHANGE_RETVAL_IF(!OLEGUID, MAPI_E_INVALID_PARAMETER, NULL);
	OPENCHANGE_RETVAL_IF(!propTag, MAPI_E_INVALID_PARAMETER, NULL);

	for (i = 0; mapi_nameid_tags[i].OLEGUID; i++) {
		if (mapi_nameid_tags[i].Name &&
		    !strcmp(mapi_nameid_tags[i].Name, Name) &&
		    !strcmp(mapi_nameid_tags[i].OLEGUID, OLEGUID)) {
			*propTag = mapi_nameid_tags[i].proptag;
			return MAPI_E_SUCCESS;
		}
	}

	OPENCHANGE_RETVAL_ERR(MAPI_E_NOT_FOUND, NULL);
}

enum e_mapi_fx_parser_state { ParserState_Entry, ParserState_HaveTag, ParserState_HavePropTag };

struct e_mapi_fx_parser_context {
	TALLOC_CTX		*mem_ctx;
	DATA_BLOB		data;	/* the data we have (so far) to parse */
	uint32_t		idx;	/* where we are up to in the data blob */
	enum e_mapi_fx_parser_state	state;
	struct SPropValue	lpProp;		/* the current property tag and value we are parsing */
	struct MAPINAMEID	namedprop;	/* the current named property we are parsing */
	bool 			enough_data;
	uint32_t		tag;
	void			*priv;
	
	/* callbacks for parser actions */
	enum MAPISTATUS (*op_marker)(uint32_t, void *);
	enum MAPISTATUS (*op_delprop)(uint32_t, void *);
	enum MAPISTATUS (*op_namedprop)(uint32_t, struct MAPINAMEID, void *);
	enum MAPISTATUS (*op_property)(struct SPropValue, void *);
};

static bool pull_uint8_t(struct e_mapi_fx_parser_context *parser, uint8_t *val)
{
	if ((parser->idx) + 1 > parser->data.length) {
		*val = 0;
		return false;
	}
	*val = parser->data.data[parser->idx];
	(parser->idx)++;
	return true;
}

static bool pull_uint16_t(struct e_mapi_fx_parser_context *parser, uint16_t *val)
{
	if ((parser->idx) + 2 > parser->data.length) {
		*val = 0;
		return false;
	}
	*val = parser->data.data[parser->idx];
	(parser->idx)++;
	*val += parser->data.data[parser->idx] << 8;
	(parser->idx)++;
	return true;
}

static bool pull_uint32_t(struct e_mapi_fx_parser_context *parser, uint32_t *val)
{
	if ((parser->idx) + 4 > parser->data.length) {
		*val = 0;
		return false;
	}
	*val = parser->data.data[parser->idx];
	(parser->idx)++;
	*val += parser->data.data[parser->idx] << 8;
	(parser->idx)++;
	*val += parser->data.data[parser->idx] << 16;
	(parser->idx)++;
	*val += parser->data.data[parser->idx] << 24;
	(parser->idx)++;
	return true;
}

static bool pull_tag(struct e_mapi_fx_parser_context *parser)
{
	return pull_uint32_t(parser, &(parser->tag));
}

static bool pull_uint8_data(struct e_mapi_fx_parser_context *parser, uint32_t read_len, uint8_t **data_read)
{
	uint32_t i;
	for (i = 0; i < read_len; i++) {
		if (!pull_uint8_t(parser, (uint8_t*)&((*data_read)[i]))) {
			return false;
		}
	}
	return true;
}

static bool pull_int64_t(struct e_mapi_fx_parser_context *parser, int64_t *val)
{
	int64_t tmp;
	if ((parser->idx) + 8 > parser->data.length) {
		*val = 0;
		return false;
	}
	*val = parser->data.data[parser->idx];
	(parser->idx)++;

	tmp = parser->data.data[parser->idx];
	*val += (tmp << 8);
	(parser->idx)++;

	tmp = parser->data.data[parser->idx];
	*val += (tmp << 16);
	(parser->idx)++;

	tmp = parser->data.data[parser->idx];
	*val += (tmp << 24);
	(parser->idx)++;

	tmp = parser->data.data[parser->idx];
	*val += (tmp << 32);
	(parser->idx)++;

	tmp = parser->data.data[parser->idx];
	*val += (tmp << 40);
	(parser->idx)++;

	tmp = parser->data.data[parser->idx];
	*val += (tmp << 48);
	(parser->idx)++;

	tmp = parser->data.data[parser->idx];
	*val += (tmp << 56);
	(parser->idx)++;

	return true;
}

static bool pull_double(struct e_mapi_fx_parser_context *parser, double *val)
{
	return pull_int64_t(parser, (int64_t *)val);
}

static bool pull_guid(struct e_mapi_fx_parser_context *parser, struct GUID *guid)
{
	int i;

	if ((parser->idx) + 16 > parser->data.length) {
		GUID_all_zero(guid);
		return false;
	}
	if (!pull_uint32_t(parser, &(guid->time_low)))
		return false;
	if (!pull_uint16_t(parser, &(guid->time_mid)))
		return false;
	if (!pull_uint16_t(parser, &(guid->time_hi_and_version)))
		return false;
	if (!pull_uint8_t(parser, &(guid->clock_seq[0])))
		return false;
	if (!pull_uint8_t(parser, &(guid->clock_seq[1])))
		return false;
	for (i = 0; i < 6; ++i) {
		if (!pull_uint8_t(parser, &(guid->node[i])))
			return false;
	}
	return true;
}

static bool pull_systime(struct e_mapi_fx_parser_context *parser, struct FILETIME *ft)
{
	struct FILETIME filetime = {0,0};

	if (parser->idx + 8 > parser->data.length ||
	    !pull_uint32_t(parser, &(filetime.dwLowDateTime)) ||
	    !pull_uint32_t(parser, &(filetime.dwHighDateTime)))
		return false;

	*ft = filetime;

	return true;
}

static bool pull_clsid(struct e_mapi_fx_parser_context *parser, struct FlatUID_r **pclsid)
{
	struct FlatUID_r *clsid;
	int i = 0;

	if (parser->idx + 16 > parser->data.length)
		return false;

	clsid = talloc_zero(parser->mem_ctx, struct FlatUID_r);
	for (i = 0; i < 16; ++i) {
		if (!pull_uint8_t(parser, &(clsid->ab[i])))
			return false;
	}

	*pclsid = clsid;

	return true;
}

static bool pull_string8(struct e_mapi_fx_parser_context *parser, char **pstr)
{
	char *str;
	uint32_t i, length;

	if (!pull_uint32_t(parser, &length) ||
	    parser->idx + length > parser->data.length)
		return false;

	str = talloc_array(parser->mem_ctx, char, length + 1);
	for (i = 0; i < length; i++) {
		if (!pull_uint8_t(parser, (uint8_t*)&(str[i]))) {
			return false;
		}
	}
	str[length] = '\0';

	*pstr = str;

	return true;
}

static bool fetch_ucs2_data(struct e_mapi_fx_parser_context *parser, uint32_t numbytes, smb_ucs2_t **data_read)
{
	if ((parser->idx) + numbytes > parser->data.length) {
		// printf("insufficient data in fetch_ucs2_data (%i requested, %zi available)\n", numbytes, (parser->data.length - parser->idx));
		return false;
	}

	*data_read = talloc_array(parser->mem_ctx, smb_ucs2_t, numbytes/2);
	memcpy(*data_read, &(parser->data.data[parser->idx]), numbytes);
	parser->idx += numbytes;
	return true;
}

static bool fetch_ucs2_nullterminated(struct e_mapi_fx_parser_context *parser, smb_ucs2_t **data_read)
{
	uint32_t idx_local = parser->idx;
	bool found = false;
	while (idx_local < parser->data.length -1) {
		smb_ucs2_t val = 0x0000;
		val += parser->data.data[idx_local];
		idx_local++;
		val += parser->data.data[idx_local] << 8;
		idx_local++;
		if (val == 0x0000) {
			found = true;
			break;
		}
	}
	if (!found)
		return false;
	return fetch_ucs2_data(parser, idx_local-(parser->idx), data_read); 
}

static bool pull_unicode(struct e_mapi_fx_parser_context *parser, char **pstr)
{
	smb_ucs2_t *ucs2_data = NULL;
	char *utf8_data = NULL;
	size_t utf8_len;
	uint32_t length;

	if (!pull_uint32_t(parser, &length) ||
	    parser->idx + length > parser->data.length)
		return false;

	ucs2_data = talloc_array(parser->mem_ctx, smb_ucs2_t, length/2);

	if (!fetch_ucs2_data(parser, length, &ucs2_data)) {
		return false;
	}
	pull_ucs2_talloc(parser->mem_ctx, &utf8_data, ucs2_data, &utf8_len);

	*pstr = utf8_data;

	return true;
}

static bool pull_binary(struct e_mapi_fx_parser_context *parser, struct Binary_r *bin)
{
	if (!pull_uint32_t(parser, &(bin->cb)) ||
	    parser->idx + bin->cb > parser->data.length)
		return false;

	bin->lpb = talloc_array(parser->mem_ctx, uint8_t, bin->cb + 1);

	return pull_uint8_data(parser, bin->cb, &(bin->lpb));
}

/*
 pull a property value from the blob, starting at position idx
*/
static bool fetch_property_value(struct e_mapi_fx_parser_context *parser, DATA_BLOB *buf, struct SPropValue *prop)
{
	switch(prop->ulPropTag & 0xFFFF) {
	case PT_NULL:
	{
		if (!pull_uint32_t(parser, &(prop->value.null)))
			return false;
		break; 
	}
	case PT_SHORT:
	{
		if (!pull_uint16_t(parser, &(prop->value.i)))
			return false;
		break;
	}
	case PT_LONG:
	{
		if (!pull_uint32_t(parser, &(prop->value.l)))
			return false;
		break;
	}
	case PT_DOUBLE:
	{
		if (!pull_double(parser, (double *)&(prop->value.dbl)))
			return false;
		break;
	}
	case PT_BOOLEAN:
	{
		if (parser->idx + 2 > parser->data.length ||
		    !pull_uint8_t(parser, &(prop->value.b)))
			return false;

		/* special case for fast transfer, 2 bytes instead of one */
		(parser->idx)++;
		break;
	}
	case PT_I8:
	{
		int64_t val;
		if (!pull_int64_t(parser, &(val)))
			return false;
		prop->value.d = val;
		break;
	}
	case PT_STRING8:
	{
		char *str = NULL;
		if (!pull_string8(parser, &str))
			return false;
		prop->value.lpszA = str;
		break;
	}
	case PT_UNICODE:
	{
		char *str = NULL;
		if (!pull_unicode (parser, &str))
			return false;
		prop->value.lpszW = str;
		break;
	}
	case PT_SYSTIME:
	{
		if (!pull_systime(parser, &prop->value.ft))
			return false;
		break;
	}
	case PT_CLSID:
	{
		if (!pull_clsid(parser, &prop->value.lpguid))
			return false;
		break;
	}
	case PT_SVREID:
	case PT_BINARY:
	{
		if (!pull_binary(parser, &prop->value.bin))
			return false;
		break;
	}
	case PT_OBJECT:
	{
		if (!pull_uint32_t(parser, &(prop->value.object)))
			return false;
		break;
	}
	case PT_ERROR:
	{
		uint32_t num;
		if (!pull_uint32_t(parser, &num))
			return false;
		prop->value.err = num;
		break;
	}
	case PT_MV_BINARY:
	{
		uint32_t i;
		if (!pull_uint32_t(parser, &(prop->value.MVbin.cValues)) ||
		    parser->idx + prop->value.MVbin.cValues * 4 > parser->data.length)
			return false;
		prop->value.MVbin.lpbin = talloc_array(parser->mem_ctx, struct Binary_r, prop->value.MVbin.cValues);
		for (i = 0; i < prop->value.MVbin.cValues; i++) {
			if (!pull_binary(parser, &(prop->value.MVbin.lpbin[i])))
				return false;
		}
		break;
	}
	case PT_MV_SHORT:
	{
		uint32_t i;
		if (!pull_uint32_t(parser, &(prop->value.MVi.cValues)) ||
		    parser->idx + prop->value.MVi.cValues * 2 > parser->data.length)
			return false;
		prop->value.MVi.lpi = talloc_array(parser->mem_ctx, uint16_t, prop->value.MVi.cValues);
		for (i = 0; i < prop->value.MVi.cValues; i++) {
			if (!pull_uint16_t(parser, &(prop->value.MVi.lpi[i])))
				return false;
		}
		break;
	}
	case PT_MV_LONG:
	{
		uint32_t i;
		if (!pull_uint32_t(parser, &(prop->value.MVl.cValues)) ||
		    parser->idx + prop->value.MVl.cValues * 4 > parser->data.length)
			return false;
		prop->value.MVl.lpl = talloc_array(parser->mem_ctx, uint32_t, prop->value.MVl.cValues);
		for (i = 0; i < prop->value.MVl.cValues; i++) {
			if (!pull_uint32_t(parser, &(prop->value.MVl.lpl[i])))
				return false;
		}
		break;
	}
	case PT_MV_STRING8:
	{
		uint32_t i;
		char *str;
		if (!pull_uint32_t(parser, &(prop->value.MVszA.cValues)) ||
		    parser->idx + prop->value.MVszA.cValues * 4 > parser->data.length)
			return false;
		prop->value.MVszA.lppszA = (const char **) talloc_array(parser->mem_ctx, char *, prop->value.MVszA.cValues);
		for (i = 0; i < prop->value.MVszA.cValues; i++) {
			str = NULL;
			if (!pull_string8(parser, &str))
				return false;
			prop->value.MVszA.lppszA[i] = str;
		}
		break;
	}
	case PT_MV_CLSID:
	{
		uint32_t i;
		if (!pull_uint32_t(parser, &(prop->value.MVguid.cValues)) ||
		    parser->idx + prop->value.MVguid.cValues * 16 > parser->data.length)
			return false;
		prop->value.MVguid.lpguid = talloc_array(parser->mem_ctx, struct FlatUID_r *, prop->value.MVguid.cValues);
		for (i = 0; i < prop->value.MVguid.cValues; i++) {
			if (!pull_clsid(parser, &(prop->value.MVguid.lpguid[i])))
				return false;
		}
		break;
	}
	case PT_MV_UNICODE:
	{
		uint32_t i;
		char *str;

		if (!pull_uint32_t(parser, &(prop->value.MVszW.cValues)) ||
		    parser->idx + prop->value.MVszW.cValues * 4 > parser->data.length)
			return false;
		prop->value.MVszW.lppszW = (const char **)  talloc_array(parser->mem_ctx, char *, prop->value.MVszW.cValues);
		for (i = 0; i < prop->value.MVszW.cValues; i++) {
			str = NULL;
			if (!pull_unicode(parser, &str))
				return false;
			prop->value.MVszW.lppszW[i] = str;
		}
		break;
	}
	case PT_MV_SYSTIME:
	{
		uint32_t i;
		if (!pull_uint32_t(parser, &(prop->value.MVft.cValues)) ||
		    parser->idx + prop->value.MVft.cValues * 8 > parser->data.length)
			return false;
		prop->value.MVft.lpft = talloc_array(parser->mem_ctx, struct FILETIME, prop->value.MVft.cValues);
		for (i = 0; i < prop->value.MVft.cValues; i++) {
			if (!pull_systime(parser, &(prop->value.MVft.lpft[i])))
				return false;
		}
		break;
	}
	default:
		printf("unhandled conversion case in fetch_property_value(): 0x%x\n", (prop->ulPropTag & 0xFFFF));
		g_return_val_if_reached(false);
	}
	return true;
}

static bool pull_named_property(struct e_mapi_fx_parser_context *parser, enum MAPISTATUS *ms)
{
	uint8_t type = 0;
	if (!pull_guid(parser, &(parser->namedprop.lpguid)))
		return false;
	/* printf("guid       : %s\n", GUID_string(parser->mem_ctx, &(parser->namedprop.lpguid))); */
	if (!pull_uint8_t(parser, &type))
		return false;
	if (type == 0) {
		parser->namedprop.ulKind = MNID_ID;
		if (!pull_uint32_t(parser, &(parser->namedprop.kind.lid)))
			return false;
		/* printf("LID dispid: 0x%08x\n", parser->namedprop.kind.lid); */
	} else if (type == 1) {
		smb_ucs2_t *ucs2_data = NULL;
		size_t utf8_len;
		parser->namedprop.ulKind = MNID_STRING;
		if (!fetch_ucs2_nullterminated(parser, &ucs2_data))
			return false;
		pull_ucs2_talloc(parser->mem_ctx, (char**)&(parser->namedprop.kind.lpwstr.Name), ucs2_data, &(utf8_len));
		parser->namedprop.kind.lpwstr.NameSize = utf8_len;
		/* printf("named: %s\n", parser->namedprop.kind.lpwstr.Name); */
	} else {
		printf("unknown named property kind: 0x%02x\n", parser->namedprop.ulKind);
		g_return_val_if_reached(false);
	}
	if (parser->op_namedprop) {
		*ms = parser->op_namedprop(parser->lpProp.ulPropTag, parser->namedprop, parser->priv);
	}

	return true;
}

/**
  \details set a callback function for marker output
*/
_PUBLIC_ void e_mapi_fxparser_set_marker_callback(struct e_mapi_fx_parser_context *parser, e_mapi_fxparser_marker_callback_t marker_callback)
{
	parser->op_marker = marker_callback;
}

/**
  \details set a callback function for delete properties output
*/
_PUBLIC_ void e_mapi_fxparser_set_delprop_callback(struct e_mapi_fx_parser_context *parser, e_mapi_fxparser_delprop_callback_t delprop_callback)
{
	parser->op_delprop = delprop_callback;
}

/**
  \details set a callback function for named properties output
*/
_PUBLIC_ void e_mapi_fxparser_set_namedprop_callback(struct e_mapi_fx_parser_context *parser, e_mapi_fxparser_namedprop_callback_t namedprop_callback)
{
	parser->op_namedprop = namedprop_callback;
}

/**
  \details set a callback function for property output
*/
_PUBLIC_ void e_mapi_fxparser_set_property_callback(struct e_mapi_fx_parser_context *parser, e_mapi_fxparser_property_callback_t property_callback)
{
	parser->op_property = property_callback;
}

/**
  \details initialise a fast transfer parser
*/
_PUBLIC_ struct e_mapi_fx_parser_context* e_mapi_fxparser_init(TALLOC_CTX *mem_ctx, void *priv)
{
	struct e_mapi_fx_parser_context *parser = talloc_zero(mem_ctx, struct e_mapi_fx_parser_context);

	parser->mem_ctx = mem_ctx;
	parser->data = data_blob_talloc_named(parser->mem_ctx, NULL, 0, "fast transfer parser");
	parser->state = ParserState_Entry;
	parser->idx = 0;
	parser->lpProp.ulPropTag = (enum MAPITAGS) 0;
	parser->lpProp.dwAlignPad = 0;
	parser->lpProp.value.l = 0;
	parser->priv = priv;

	return parser;
}

/**
  \details parse a fast transfer buffer
*/
_PUBLIC_ enum MAPISTATUS e_mapi_fxparser_parse(struct e_mapi_fx_parser_context *parser, DATA_BLOB *fxbuf)
{
	enum MAPISTATUS ms = MAPI_E_SUCCESS;

	data_blob_append(parser->mem_ctx, &(parser->data), fxbuf->data, fxbuf->length);
	parser->enough_data = true;
	while(ms == MAPI_E_SUCCESS && (parser->idx < parser->data.length) && parser->enough_data) {
		uint32_t idx = parser->idx;

		switch(parser->state) {
			case ParserState_Entry:
			{
				if (pull_tag(parser)) {
					/* printf("tag: 0x%08x\n", parser->tag); */
					parser->state = ParserState_HaveTag;
				} else {
					parser->enough_data = false;
					parser->idx = idx;
				}
				break;
			}
			case ParserState_HaveTag:
			{
				switch (parser->tag) {
					case PidTagStartTopFld:
					case PidTagStartSubFld:
					case PidTagEndFolder:
					case PidTagStartMessage:
					case PidTagStartFAIMsg:
					case PidTagEndMessage:
					case PidTagStartRecip:
					case PidTagEndToRecip:
					case PidTagNewAttach:
					case PidTagEndAttach:
					case PidTagStartEmbed:
					case PidTagEndEmbed:
						if (parser->op_marker) {
							ms = parser->op_marker(parser->tag, parser->priv);
						}
						parser->state = ParserState_Entry;
						break;
					case PidTagFXDelProp:
					{
						uint32_t tag;
						if (pull_uint32_t(parser, &tag)) {
							if (parser->op_delprop) {
								ms = parser->op_delprop(tag, parser->priv);
							}
							parser->state = ParserState_Entry;
						} else {
							parser->enough_data = false;
							parser->idx = idx;
						}
						break;
					}
					default:
					{
						/* standard property thing */
						parser->lpProp.ulPropTag = (enum MAPITAGS) parser->tag;
						parser->lpProp.dwAlignPad = 0;
						if ((parser->lpProp.ulPropTag >> 16) & 0x8000) {
							/* this is a named property */
							// printf("tag: 0x%08x\n", parser->tag);
							// TODO: this should probably be a separate parser state
							// TODO: this needs to return the named property
							if (pull_named_property(parser, &ms)) {
								parser->state = ParserState_HavePropTag;
							} else {
								parser->enough_data = false;
								parser->idx = idx;
							}
						} else {
							parser->state = ParserState_HavePropTag;
						}
					}
				}
				break;
			}
			case ParserState_HavePropTag:
			{
				if (fetch_property_value(parser, &(parser->data), &(parser->lpProp))) {
					// printf("position %i of %zi\n", parser->idx, parser->data.length);
					if (parser->op_property) {
						ms = parser->op_property(parser->lpProp, parser->priv);
					}
					parser->state = ParserState_Entry;
				} else {
					parser->enough_data = false;
					parser->idx = idx;
				}
				break;
			}
		}
	}
	{
		// Remove the part of the buffer that we've used
		uint32_t remainder_len = parser->data.length - parser->idx;
		DATA_BLOB remainder = data_blob_talloc_named(parser->mem_ctx, &(parser->data.data[parser->idx]), remainder_len, "fast transfer parser");
		data_blob_free(&(parser->data));
		parser->data = remainder;
		parser->idx = 0;
	}

	return ms;
}
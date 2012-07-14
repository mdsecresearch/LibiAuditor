
//
//  LibiAuditor
//
//  Created by Dominic Chell on 13/02/2012.
//  Copyright (c) 2012 MDSec Consulting Ltd. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CaptainHook/CaptainHook.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <AddressBook/AddressBook.h>
#import <substrate.h>
#import "Database.h"

@interface LibiAuditor : NSObject

@end

@implementation LibiAuditor

-(id)init
{
	if ((self = [super init]))
	{
	}

    return self;
}

@end

@class NSURLConnection;
@class UIApplication;
@class NSData;
@class NSXMLParser;
@class CLLocationManager;
@class NSURL;
@class NSURLRequest;

CHDeclareClass(NSURLConnection);
CHDeclareClass(UIApplication);
CHDeclareClass(NSData);
CHDeclareClass(NSXMLParser);
CHDeclareClass(CLLocationManager);
CHDeclareClass(NSURL);
CHDeclareClass(NSURLRequest);

/********** CHECK FOR SELF SIGNED CERTS **********/

CHOptimizedMethod(1, self, BOOL, NSURLConnection, continueWithoutCredentialForAuthenticationChallenge, NSURLAuthenticationChallenge *, challenge)
{
    NSString *issueTitle = @"Self Signed Certificates Permitted";
    NSString *issueDesc = [NSString stringWithFormat:@"The application permitted a self-signed certificate when attempting to connect the host %@.", [challenge.protectionSpace host]];
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
    
	return CHSuper(1, NSURLConnection, continueWithoutCredentialForAuthenticationChallenge, challenge);
}

/********** CHECK FOR URL HANDLERS **********/

CHOptimizedMethod(1, self, BOOL, UIApplication, handleOpenURL, NSURL *, url )
{
    NSString *issueTitle = @"URL Handler Invoked";
    NSString *issueDesc = [NSString stringWithFormat:@"The application opened the following URL by use of a URL handler: %@", [url absoluteString]];
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];

	return CHSuper(1, UIApplication, handleOpenURL, url);
}

CHOptimizedMethod(3, self, BOOL, UIApplication, openURL, NSURL *, url, sourceApplication, NSString *, sourceApplication, annotation, id, annotation)
{
    NSString *issueTitle = @"URL Handler Invoked";
    NSString *issueDesc = [NSString stringWithFormat:@"The application opened the following URL by use of a URL handler: %@\r\nThe URL was invoked from the source application %@.", [url absoluteString], sourceApplication];
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
	return CHSuper(3, UIApplication, openURL, url, sourceApplication, sourceApplication, annotation, annotation);
}

/********** DATA STORAGE **********/

CHOptimizedMethod(2, self, BOOL, NSData, writeToURL, NSString *, path, atomically, BOOL, flag)
{
    NSString *issueTitle = @"Insecure File System Storage";
    NSString *issueDesc = [NSString stringWithFormat:@"The application wrote a file to the file system without encryption using the writeToURL method, the contents of this file may not be encrypted. The file was written to the following path: \n%@.", path];
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
    
	return CHSuper(2, NSData, writeToURL, path, atomically, flag);
}

CHOptimizedMethod(2, self, BOOL, NSData, writeToFile, NSString *, path, atomically, BOOL, flag)
{
    NSString *issueTitle = @"Insecure File System Storage";
    NSString *issueDesc = [NSString stringWithFormat:@"The application wrote a file to the file system without encryption using the writeToFile method, the contents of this file may not be encrypted. The file was written to the following path: \n%@.", path];
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];

	return CHSuper(2, NSData, writeToFile, path, atomically, flag);
}

CHOptimizedMethod(3, self, BOOL, NSData, writeToURL, NSString *, path, options, NSDataWritingOptions *, options, error, NSError *, errorPtr)
{
    NSString *issueTitle = @"File System Storage using writeToURL and NSDataWritingOptions";
    NSString *issueDesc;
    switch((int)options)
    {
        case NSDataWritingFileProtectionNone:
            issueDesc = [NSString stringWithFormat:@"The application wrote a file to the file system using the NSDataWritingFileProtectionNone data protection option. In this case, the file is not stored in an encrypted format and may be accessed at boot time and while the device is unlocked. The file was written to the following path: \n%@.", path];
            break;
        case NSDataWritingFileProtectionComplete:
            issueDesc = [NSString stringWithFormat:@"The application wrote a file to the file system using the NSDataWritingFileProtectionComplete data protection option. In this case, the file is stored in an encrypted format and may be read from or written to only while the device is unlocked. At all other times, attempts to read and write to the file result in failure. The file was written to the following path: \n%@.", path];
            break;
        case NSDataWritingFileProtectionCompleteUnlessOpen:
            issueDesc = [NSString stringWithFormat:@"The application wrote a file to the file system using the NSDataWritingFileProtectionCompleteUnlessOpen data protection option. In this case, the file cannot be opened for reading or writing when the device is locked, although new files can be created with this class. If one of these files is open when the device is locked, reading and writing are still allowed. The file was written to the following path: \n%@.", path];
            break;
        case NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication:
            issueDesc = [NSString stringWithFormat:@"The application wrote a file to the file system using the NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication data protection option. In this case, the file can be read or written to while the device is locked, but while it is booting up, they have protection equivalent to NSDataWritingFileProtectionComplete. The file was written to the following path: \n%@.", path];
            break;
        default:
            issueDesc = [NSString stringWithFormat:@"A file was written to the file system using one of the NSDataWritingOptions options, however iAuditor was unable to determine the option used. The file was written to the following path: \n%@.", path];
            break;
    }
    
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
    
	return CHSuper(3, NSData, writeToURL, path, options, options, error, errorPtr);
}

CHOptimizedMethod(3, self, BOOL, NSData, writeToFile, NSString *, path, options, NSDataWritingOptions *, options, error, NSError *, errorPtr)
{
    NSString *issueTitle = @"File System Storage using writeToFile and NSDataWritingOptions";
    NSString *issueDesc;
    switch((int)options)
    {
        case NSDataWritingFileProtectionNone:
            issueDesc = [NSString stringWithFormat:@"The application wrote a file to the file system using the NSDataWritingFileProtectionNone data protection option. In this case, the file is not stored in an encrypted format and may be accessed at boot time and while the device is unlocked. The file was written to the following path: \n%@.", path];
            break;
        case NSDataWritingFileProtectionComplete:
            issueDesc = [NSString stringWithFormat:@"The application wrote a file to the file system using the NSDataWritingFileProtectionComplete data protection option. In this case, the file is stored in an encrypted format and may be read from or written to only while the device is unlocked. At all other times, attempts to read and write to the file result in failure. The file was written to the following path: \n%@.", path];
            break;
        case NSDataWritingFileProtectionCompleteUnlessOpen:
            issueDesc = [NSString stringWithFormat:@"The application wrote a file to the file system using the NSDataWritingFileProtectionCompleteUnlessOpen data protection option. In this case, the file cannot be opened for reading or writing when the device is locked, although new files can be created with this class. If one of these files is open when the device is locked, reading and writing are still allowed. The file was written to the following path: \n%@.", path];
            break;
        case NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication:
            issueDesc = [NSString stringWithFormat:@"The application wrote a file to the file system using the NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication data protection option. In this case, the file can be read or written to while the device is locked, but while it is booting up, they have protection equivalent to NSDataWritingFileProtectionComplete. The file was written to the following path: \n%@.", path];
            break;
        default:
            issueDesc = [NSString stringWithFormat:@"A file was written to the file system using one of the NSDataWritingOptions options, however iAuditor was unable to determine the option used. The file was written to the following path: \n%@.", path];
            break;
    }
    
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];

	return CHSuper(3, NSData, writeToFile, path, options, options, error, errorPtr);
}

/********** XXE **********/

CHOptimizedMethod(1, self, BOOL, NSXMLParser, setShouldResolveExternalEntities, BOOL, shouldResolveExternalEntities )
{
    if(shouldResolveExternalEntities == TRUE)
    {
        NSString *issueTitle = @"External XML Entity Parsing";
        NSString *issueDesc = @"The application enables the process of external entities using the setShouldResolveExternalEntities method. If the XML being processed is user controlled, the application may be susceptible to XXE injection attacks.";
        Database *iadb = [[Database alloc] init];
        [iadb setName:issueTitle];
        [iadb setDescription:issueDesc];
        [iadb addIssue];
        [iadb release];
    }
	return CHSuper(1, NSXMLParser, setShouldResolveExternalEntities, shouldResolveExternalEntities);
}

/********* GeoLocation **********/

CHOptimizedMethod(0, self, void, CLLocationManager, startUpdatingLocation)
{
    NSString *issueTitle = @"Location Information in Use";
    NSString *issueDesc = @"The application makes use of location information via the CLLocationManager class, if location data is logged to the device or server this may raise privacy concerns.";
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
	return CHSuper(0, CLLocationManager, startUpdatingLocation);
}

/********* Privacy Checks **********/

MSHook(bool, ABAddressBookAddRecord, ABAddressBookRef addressBook, ABRecordRef record, CFErrorRef *error)
{
    NSString *issueTitle = @"Privacy - Adding to Addressbook";
    NSString *issueDesc = @"The application adds a record to the phone's address book. Accessing the addressbook raises privacy concerns and should be investigated.";
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
    return _ABAddressBookAddRecord(addressBook, record, error);
}

MSHook(bool, ABAddressBookHasUnsavedChanges, ABAddressBookRef addressBook)
{
    NSString *issueTitle = @"Privacy - ABAddressBookHasUnsavedChanges used on Addressbook";
    NSString *issueDesc = @"The application uses ABAddressBookHasUnsavedChanges to 'touch' the phone's address book. Accessing the addressbook raises privacy concerns and should be investigated.";
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
	return _ABAddressBookHasUnsavedChanges(addressBook);
}

MSHook(void, ABAddressBookRegisterExternalChangeCallback, ABAddressBookRef addressBook, ABExternalChangeCallback callback, void *context)
{
    NSString *issueTitle = @"Privacy - Application is monitoring the addressbook";
    NSString *issueDesc = @"The application registers a callback to receive addressbook notifications. Accessing the addressbook raises privacy concerns and should be investigated.";
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
	return _ABAddressBookRegisterExternalChangeCallback(addressBook, callback, context);
}

MSHook(bool, ABAddressBookRemoveRecord, ABAddressBookRef addressBook, ABRecordRef record, CFErrorRef *error)
{
    NSString *issueTitle = @"Privacy - Application Removes an Addressbook Record";
    NSString *issueDesc = @"The application removes a record from the addressbook. Accessing the addressbook raises privacy concerns and should be investigated.";
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
    return _ABAddressBookRemoveRecord(addressBook, record, error);
}

MSHook(bool, ABAddressBookSave, ABAddressBookRef addressBook, CFErrorRef *error)
{
    NSString *issueTitle = @"Privacy - Application Saves the Addressbook Record";
    NSString *issueDesc = @"The application saved changes to the addressbook. Accessing the addressbook raises privacy concerns and should be investigated.";
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
    return _ABAddressBookSave(addressBook, error);
}

MSHook(CFArrayRef, ABAddressBookCopyArrayOfAllPeople, ABAddressBookRef addressBook)
{
    NSString *issueTitle = @"Privacy - Application Accesses Person Records";
    NSString *issueDesc = @"The application accesses all person records in the address book using ABAddressBookCopyArrayOfAllPeople. Accessing the addressbook raises privacy concerns and should be investigated.";
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
    return _ABAddressBookCopyArrayOfAllPeople(addressBook);
}

MSHook(CFArrayRef, ABAddressBookCopyArrayOfAllPeopleInSource, ABAddressBookRef addressBook, ABRecordRef source)
{
    NSString *issueTitle = @"Privacy - Application Accesses Person Records";
    NSString *issueDesc = @"The application accesses all person records in the address book using ABAddressBookCopyArrayOfAllPeopleInSource. Accessing the addressbook raises privacy concerns and should be investigated.";
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
    return _ABAddressBookCopyArrayOfAllPeopleInSource(addressBook, source);
}

MSHook(CFArrayRef, ABAddressBookCopyArrayOfAllPeopleInSourceWithSortOrdering, ABAddressBookRef addressBook, ABRecordRef source, ABPersonSortOrdering sortOrdering)
{
    NSString *issueTitle = @"Privacy - Application Accesses Person Records";
    NSString *issueDesc = @"The application accesses all person records in the address book using ABAddressBookCopyArrayOfAllPeopleInSourceWithSortOrdering. Accessing the addressbook raises privacy concerns and should be investigated.";
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
	return _ABAddressBookCopyArrayOfAllPeopleInSourceWithSortOrdering(addressBook, source, sortOrdering);
}

MSHook(CFArrayRef, ABAddressBookCopyPeopleWithName, ABAddressBookRef addressBook, CFStringRef name)
{
    NSString *issueTitle = @"Privacy - Application Accesses Person Records";
    NSString *issueDesc = @"The application accesses all person records in the address book using ABAddressBookCopyPeopleWithName. Accessing the addressbook raises privacy concerns and should be investigated.";
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];

	return _ABAddressBookCopyPeopleWithName(addressBook, name);
}

MSHook(ABRecordRef, ABAddressBookGetPersonWithRecordID, ABAddressBookRef addressBook, ABRecordID recordID)
{
    NSString *issueTitle = @"Privacy - Application Accesses Person Records";
    NSString *issueDesc = @"The application accesses all person records in the address book using ABAddressBookGetPersonWithRecordID. Accessing the addressbook raises privacy concerns and should be investigated.";
    Database *iadb = [[Database alloc] init];
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
	return _ABAddressBookGetPersonWithRecordID(addressBook, recordID);
}

/********* NSLog **********/

MSHook(void, NSLogv, NSString *format, va_list args)
{
    NSString *issueTitle = @"Application has Logging Enabled";
    NSMutableString *issueDesc = [NSMutableString string];
    [issueDesc appendFormat:@"The application writes data to the Apple System Log, this data can be accessed by any application installed on the device. The following string was logged:\n\t"];
    Database *iadb = [[Database alloc] init];

    char *ptr = (char*)[format UTF8String];
    char *s, *c;
    int d,i;
    NSObject *obj;
    va_list args2;
    va_copy(args2, args);
    
    while(*ptr)
    {
        if(*ptr != '%')
        {
            [issueDesc appendFormat:@"%c",*ptr];
        }
        else
        {
            ptr++;
            switch(*ptr)
            {
                case 's':  
                    s = va_arg(args, char *);
                    [issueDesc appendFormat:@"%s",s];
                    break;
                case 'd':
                    d = va_arg(args, int);
                    [issueDesc appendFormat:@"%d",d];
                    break;
                case 'c':
                    c = va_arg(args, char*);
                    [issueDesc appendFormat:@"%c",c];
                    break;
                case 'i':
                    i = va_arg(args, int);
                    [issueDesc appendFormat:@"%i",i];
                    break;
                case '@':
                    obj = va_arg(args, NSObject*);
                    if([obj isKindOfClass:[NSString class]])
                    {
                        [issueDesc appendString:(NSString*)obj];
                    }
                    break;
                default:
                    break;
            }
        }
        ptr++;
    }
   
    [iadb setName:issueTitle];
    [iadb setDescription:issueDesc];
    [iadb addIssue];
    [iadb release];
    
    return _NSLogv(format, args2);
}

/********* NSURL HTTP URLs **********/

CHOptimizedMethod(1, self, id, NSURLRequest, requestWithURL, NSURL*, theURL)
{
    if(([[theURL absoluteString] rangeOfString:@"http://"].location) != NSNotFound)
    {
        NSString *issueTitle = @"HTTP URL Created";
    
        NSString *issueDesc = [NSString stringWithFormat:@"The application initiates a URL request without using SSL. Any communications with this URL will traverse the network in clear text and may be susceptible to capture from a suitably positioned attacker. The created URL is:\n\t%s", [[theURL absoluteString] UTF8String]];
    
        Database *iadb = [[Database alloc] init];
        [iadb setName:issueTitle];
        [iadb setDescription:issueDesc];
        [iadb addIssue];
        [iadb release];
    }
    return CHSuper(1, NSURLRequest, requestWithURL, theURL);
}

CHOptimizedMethod(1, self, id, NSURL, URLWithString, NSString *, URLString)
{
    if(([URLString rangeOfString:@"http://"].location) != NSNotFound)
    {
        NSString *issueTitle = @"HTTP URL Created";
        NSString *issueDesc = [NSString stringWithFormat:@"The application initiates a URL request without using SSL. Any communications with this URL will traverse the network in clear text and may be susceptible to capture from a suitably positioned attacker. The created URL is:\n\t%s", [URLString UTF8String]];
    
        Database *iadb = [[Database alloc] init];
        [iadb setName:issueTitle];
        [iadb setDescription:issueDesc];
        [iadb addIssue];
        [iadb release];
    }
    
	return CHSuper(1, NSURL, URLWithString, URLString);
}

CHOptimizedMethod(2, self, NSURLConnection*, NSURLConnection, initWithRequest, NSURLRequest *, request, delegate, id, myid)
{
    if(([[[request URL] absoluteString] rangeOfString:@"http://"].location) != NSNotFound)
    {
        NSString *issueTitle = @"HTTP URL Created";
        NSString *issueDesc = [NSString stringWithFormat:@"The application initiates a URL request without using SSL. Any communications with this URL will traverse the network in clear text and may be susceptible to capture from a suitably positioned attacker. The created URL is:\n\t%s", [[[request URL] absoluteString] UTF8String]];
    
        Database *iadb = [[Database alloc] init];
        [iadb setName:issueTitle];
        [iadb setDescription:issueDesc];
        [iadb addIssue];
        [iadb release];
	}
    
    return CHSuper(2, NSURLConnection, initWithRequest, request, delegate, myid);
}

CHOptimizedMethod(1, self, NSData *, NSData, dataWithContentsOfURL, NSURL *, aURL)
{
    if(([[aURL absoluteString] rangeOfString:@"http://"].location) != NSNotFound)
    {
        NSString *issueTitle = @"HTTP URL Created";
        NSString *issueDesc = [NSString stringWithFormat:@"The application initiates a URL request without using SSL. Any communications with this URL will traverse the network in clear text and may be susceptible to capture from a suitably positioned attacker. The created URL is:\n\t%s", [[aURL absoluteString] UTF8String]];
    
        Database *iadb = [[Database alloc] init];
        [iadb setName:issueTitle];
        [iadb setDescription:issueDesc];
        [iadb addIssue];
        [iadb release];
	}
    return CHSuper(1, NSData, dataWithContentsOfURL, aURL);
}

CHConstructor
{
	NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
	
	CHLoadClass(NSURLConnection);
    CHLoadClass(UIApplication);
    CHLoadClass(NSData);
    CHLoadClass(NSXMLParser);
    CHLoadClass(NSURLRequest);
    CHLoadClass(NSURL);
    CHLoadClass(CLLocationManager);
    
    CHHook(1, NSURLConnection, continueWithoutCredentialForAuthenticationChallenge);
	CHHook(1, UIApplication, handleOpenURL);
	CHHook(3, UIApplication, openURL, sourceApplication, annotation);
    CHHook(2, NSData, writeToURL, atomically);
    CHHook(2, NSData, writeToFile, atomically);
    CHHook(3, NSData, writeToURL, options, error);
    CHHook(3, NSData, writeToFile, options, error);
    CHHook(1, NSXMLParser, setShouldResolveExternalEntities);
    CHHook(0, CLLocationManager, startUpdatingLocation);

    CHHook(1, NSURL, URLWithString);
    CHHook(1, NSURLRequest, requestWithURL);
    CHHook(2, NSURLConnection, initWithRequest, delegate);
    CHHook(1, NSData, dataWithContentsOfURL);
    
    MSHookFunction(&ABAddressBookAddRecord, MSHake(ABAddressBookAddRecord));
    MSHookFunction(&ABAddressBookHasUnsavedChanges, MSHake(ABAddressBookHasUnsavedChanges));
    MSHookFunction(&ABAddressBookRegisterExternalChangeCallback, MSHake(ABAddressBookRegisterExternalChangeCallback));
    MSHookFunction(&ABAddressBookRemoveRecord, MSHake(ABAddressBookRemoveRecord));
    MSHookFunction(&ABAddressBookSave, MSHake(ABAddressBookSave));
    MSHookFunction(&ABAddressBookCopyArrayOfAllPeople, MSHake(ABAddressBookCopyArrayOfAllPeople));
    MSHookFunction(&ABAddressBookCopyArrayOfAllPeopleInSource, MSHake(ABAddressBookCopyArrayOfAllPeopleInSource));
    
    MSHookFunction(&ABAddressBookCopyArrayOfAllPeopleInSourceWithSortOrdering, MSHake(ABAddressBookCopyArrayOfAllPeopleInSourceWithSortOrdering));
    MSHookFunction(&ABAddressBookCopyPeopleWithName, MSHake(ABAddressBookCopyPeopleWithName));
    MSHookFunction(&ABAddressBookGetPersonWithRecordID, MSHake(ABAddressBookGetPersonWithRecordID));
    MSHookFunction(&NSLogv, MSHake(NSLogv));
    
    [pool drain];
}

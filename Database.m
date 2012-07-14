
//  LibiAuditor
//
//  Created by Dominic Chell on 13/02/2012.
//  Copyright (c) 2012 MDSec Consulting Ltd. All rights reserved.
//

#import "Database.h"

@implementation Database

-(void) setName:(NSString *)n;
{
    name = n;
}

-(void) setDescription:(NSString *)n;
{
    description = n;
}

-(BOOL) addIssue;
{
    sqlite3 * iaDatabase;
    NSFileManager *filemgr = [NSFileManager defaultManager];
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [NSString stringWithFormat: @"%@/iauditor.db", [paths objectAtIndex:0]];
    const char *dbpath = [documentsDirectory UTF8String];
    if ([filemgr fileExistsAtPath: documentsDirectory ] == YES)
    {
        if (sqlite3_open(dbpath, &iaDatabase) == SQLITE_OK)
        {
            NSString *SQL = [NSString stringWithFormat:@"INSERT INTO ISSUES(name,description) VALUES(\"%@\", \"%@\")", name, description]; 
            char *errMsg;
            const char *sql_stmt = [SQL UTF8String];
            
            if (sqlite3_exec(iaDatabase, sql_stmt, NULL, NULL, &errMsg) != SQLITE_OK)
            {
                printf("ERROR: Unable to add issue to iAuditor database");
            }
            sqlite3_close(iaDatabase);
        } else {
            printf("ERROR: Unable to open iAuditor database");
        }
    }
    else
    {
        if (sqlite3_open(dbpath, &iaDatabase) == SQLITE_OK)
        {
            NSString *SQL = @"CREATE TABLE IF NOT EXISTS ISSUES (ID INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT)"; 
            char *errMsg;
            const char *sql_stmt = [SQL UTF8String];
            
            if (sqlite3_exec(iaDatabase, sql_stmt, NULL, NULL, &errMsg) != SQLITE_OK)
            {
                printf("ERROR: Unable to add issue to iAuditor database");
            }
           
            NSString *InsertSQL = [NSString stringWithFormat:@"INSERT INTO ISSUES(name,description) VALUES(\"%@\", \"%@\")", name, description];
            const char *insertsql_stmt = [InsertSQL UTF8String];
            
            if (sqlite3_exec(iaDatabase, insertsql_stmt, NULL, NULL, &errMsg) != SQLITE_OK)
            {
                printf("ERROR: Unable to add issue to iAuditor database");
            }

            
            sqlite3_close(iaDatabase);
            
        } else {
            printf("ERROR: Unable to open iAuditor database");
        }
    }
    
    [filemgr release];
    
    return TRUE;
}

@end

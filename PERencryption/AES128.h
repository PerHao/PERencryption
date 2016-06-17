//
//  AES128.h
//  ExpressTransport
//
//  Created by per on 16/4/29.
//  Copyright © 2016年 per. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AES128 : NSObject
+(NSString *)AES128Encrypt:(NSString *)plainText withPassword:(NSString *)password withIv:(NSString *)iv;


+(NSString *)AES128Encrypt:(NSString *)plainText withPassword:(NSString *)password;
+(NSString *)AES128Encrypt:(NSString *)plainText withIv:(NSString *)iv;
+(NSString *)AES128Encrypt:(NSString *)plainText;
+(NSString *)AES128Decrypt:(NSString *)encryptText;
+(NSString *)AES128Decrypt:(NSString *)encryptText withPassword:(NSString *)password;
@end

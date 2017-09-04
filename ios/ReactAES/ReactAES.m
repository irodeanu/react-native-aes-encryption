//
//  ReactAES.m
//  ReactAES
//
//  Created by Yungui Dai on 16/6/19.
//  Copyright © 2016年 fanday. All rights reserved.
//

#import "ReactAES.h"
#import "CryptLib.h"
#import "NSData+Base64.h"
#import "NSString+Base64.h"
#import "NSData+CommonCrypto.h"
#import "RCTLog.h"

@implementation ReactAES

RCT_EXPORT_MODULE(ReactAES);

RCT_EXPORT_METHOD(encrypt:(NSString *)plainText key:(NSString *)key iv:(NSString *)iv resolver:(RCTPromiseResolveBlock)resolve
rejecter:(RCTPromiseRejectBlock)reject) {
        reject(@"-1", @"encrypt failed", nil);
}

RCT_EXPORT_METHOD(decrypt:(NSString *)encryptedText key:(NSString *)key iv:(NSString *)iv resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {

    NSData *encryptedData = [NSData base64DataFromString:encryptedText];
    NSData *decryptedData = [encryptedData decryptedAES256DataUsingKey:[[key dataUsingEncoding:NSUTF8StringEncoding] SHA256Hash] error:nil];
    NSString *str = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];

    if(str){
        resolve(str);
    }else{
        reject(@"-1", @"decrypt failed", nil);
    }

}

RCT_EXPORT_METHOD(generateRandomIV:(NSInteger)length resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    resolve(@"");
}

RCT_REMAP_METHOD(getEmptyIV,
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    resolve(@"");
}

RCT_EXPORT_METHOD(md5:(NSString *)input resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSData *data = [[input dataUsingEncoding:NSUTF8StringEncoding] MD5Sum];
    NSString *md5= [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if(md5){
        resolve(md5);
    }else{
        reject(@"-1", @"md5 failed", nil);
    }

}

RCT_EXPORT_METHOD(sha256:(NSString *)key length:(NSInteger) length resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    resolve(@"");
}

@end

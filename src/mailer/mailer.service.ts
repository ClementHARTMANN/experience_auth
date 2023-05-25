import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
@Injectable()
export class MailerService {

    private async transporter(){
        const testAccount = await nodemailer.createTestAccount()
        const transport = nodemailer.createTransport({
            host : "localhost",
            port : 1025,
            ignoreTLS : true,
            auth : {
                user : testAccount.user,
                pass : testAccount.pass,
            },
        
        })
        return transport;
    }

    async sendSignupConfirmation(userEmail: string){
        (await this.transporter()).sendMail({
            from : "app@localhost.com",
            to : userEmail,
            subject: 'Inscription',
            html: '<h3>Confirmation of inscription</h3>',
        });
    }

    async sendResetPassword(userEmail : string, url : string, code : string){
        (await this.transporter()).sendMail({
            from : "app@localhost.com",
            to : userEmail,
            subject: 'reset password',
            html: `
                <a href="${url}">Reset password</a>
                <p>Secret code <strong>${code}</strong></p>
                <p>Code will expire in 15 MINUTES</p>
            `,
        });
    }
}

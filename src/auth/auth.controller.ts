import { Controller, Post } from '@nestjs/common';
import { Body } from '@nestjs/common/decorators';
import { SignupDto } from './dto/signupDto';
import { SigninDto } from './dto/signinDto';
import { AuthService } from './auth.service';
import { ResetPasswordDemandDto } from './dto/resetPasswordDemandDto';
import { ResetPasswordConfirmationDto } from './dto/resetPasswordConfirmationDto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService : AuthService) {}

    @Post("signup")
    signup(@Body() signupDto : SignupDto){
        return this.authService.signup(signupDto);
    }
    @Post("signin")
    signin(@Body() signinDto : SigninDto){
        return this.authService.signin(signinDto);
    }
    @Post("reset-password")
    resetPasswordDemand(@Body() resetPasswordDemandDto : ResetPasswordDemandDto){
        return this.authService.resetPasswordDemand(resetPasswordDemandDto)
    }
    @Post("reset-password-confirmation")
    resetPasswordConfirmation(@Body() resetPasswordConfirmationDto : ResetPasswordConfirmationDto){
        return this.authService.resetPasswordConfirmation(resetPasswordConfirmationDto)
    }
}

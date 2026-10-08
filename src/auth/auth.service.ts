import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '../generated/prisma/client';
import * as bcrypt from 'bcrypt';
import { RpcException } from '@nestjs/microservices';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from '../config';


@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit{

    private readonly logger =  new Logger('AuthService');

    constructor(
        private readonly jwtService: JwtService
    ){
        super();
    }

    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDB connected');
    }

    async signJWT(payload: JwtPayload){
        return this.jwtService.sign(payload);
    }

    async verifyToken(token:string){
        try {
            const {sub, iat, exp, ...user} = this.jwtService.verify(token,{
                secret: envs.jwtSecret
            });

            return{
                user:user,
                token: await this.signJWT(user)
            }

        } catch (error) {
            throw new RpcException({
                status:401,
                message:'Invalid Token'
            })
        }
    }


    async registerUser(registerUserDto: RegisterUserDto){
        const { name, email, password } = registerUserDto;
        try {
            const user = await this.user.findUnique({
                where: {
                    email: email
                }
            });

            if(user){
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                });
            }

            const newUser = await this.user.create({
                data: {
                    email: email,
                    name: name,
                    password: bcrypt.hashSync(password, 10)
                }
            });

            const { password: _, ...rest} = newUser;

            return{
                user: rest,
                token: await this.signJWT(rest)
            }


        } catch (error : any) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }


    async loginUser(loginUserDto:LoginUserDto){
        const { email, password } = loginUserDto;
        try {
            const user = await this.user.findUnique({
                where: {
                    email: email
                }
            });

            if(!user){
                throw new RpcException({
                    status: 400,
                    message: 'User not found'
                });
            }

            const isPasswordMatch =  bcrypt.compareSync(password, user.password);

            if(!isPasswordMatch){
                throw new RpcException({
                    status: 400,
                    message: 'Invalid credentials'
                });
            }

            const { password: _, ...rest} = user;

            return{
                user: rest,
                token: await this.signJWT(rest)
            }

        } catch (error : any) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }


}

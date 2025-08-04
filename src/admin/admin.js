import AdminJS from 'adminjs';
import AdminJSExpress from '@adminjs/express';
import { Database, Resource } from '@adminjs/mongoose';
import mongoose from 'mongoose';

import User from '../models/user.js';
import Profile from '../models/profile.js';
import Posts from '../models/posts.js';
import Events from '../models/events.js';
import Notification from '../models/notification.js';
import Subscription from '../models/subscription.js';
import Transaction from '../models/transaction.js';
import BlacklistedToken from '../models/blacklistedToken.js';

AdminJS.registerAdapter({ Resource, Database });

const adminJs = new AdminJS({
  resources: [
    {
      resource: User,
      options: {
        properties: {
          _id: { isVisible: { list: false, filter: false, show: true, edit: false } },
          fullName: { isVisible: { list: true, filter: true, show: true, edit: true } },
          email: { isVisible: { list: true, filter: true, show: true, edit: true } },
          mobileNumber: { isVisible: { list: true, filter: true, show: true, edit: true } },
          mpin: { isVisible: { list: true, filter: false, show: true, edit: true } },
          // Hide all other fields from edit/new, but show in show view
          otp: { isVisible: { list: false, filter: false, show: true, edit: false } },
          otpVerified: { isVisible: { list: false, filter: false, show: true, edit: false } },
          otpExpiresAt: { isVisible: { list: false, filter: false, show: true, edit: false } },
          refreshToken: { isVisible: { list: false, filter: false, show: true, edit: false } },
          refreshTokenExpiresAt: { isVisible: { list: false, filter: false, show: true, edit: false } },
          isAdmin: { isVisible: { list: true, filter: true, show: true, edit: true } },
          profile: { isVisible: { list: false, filter: false, show: true, edit: false } },
          connections: { isVisible: { list: false, filter: false, show: true, edit: false } },
          eventsAttended: { isVisible: { list: false, filter: false, show: true, edit: false } },
          posts: { isVisible: { list: false, filter: false, show: true, edit: false } },
          transactions: { isVisible: { list: false, filter: false, show: true, edit: false } },
          subscription: { isVisible: { list: false, filter: false, show: true, edit: false } },
          createdAt: { isVisible: { list: false, filter: false, show: true, edit: false } },
          updatedAt: { isVisible: { list: false, filter: false, show: true, edit: false } },
        },
        actions: {
          new: {
            isAccessible: true,
            before: async (request) => {
              if (request.payload) {
                let { fullName, email, mobileNumber, mpin, isAdmin } = request.payload;
                if (mpin !== undefined && mpin !== null) mpin = String(mpin);
                request.payload = { fullName, email, mobileNumber, mpin, isAdmin };
              }
              return request;
            },
            after: async (response, request, context) => {
              // Automatically create a profile for the new user
              if (response.record && response.record.id) {
                const userId = response.record.id;
                const Profile = (await import('../models/profile.js')).default;
                const profile = await Profile.create({ user: userId });
                // Optionally update the user with the profile id
                const User = (await import('../models/user.js')).default;
                await User.findByIdAndUpdate(userId, { profile: profile._id });
              }
              return response;
            },
          },
          edit: {
            isAccessible: true,
            before: async (request) => {
              if (request.payload) {
                let { fullName, email, mobileNumber, mpin, isAdmin } = request.payload;
                if (mpin !== undefined && mpin !== null) mpin = String(mpin);
                request.payload = { fullName, email, mobileNumber, mpin, isAdmin };
              }
              return request;
            },
            after: async (response) => response,
          },
          delete: {
            isAccessible: true,
            after: async (response, request, context) => {
              // Handle both single and bulk delete
              const Profile = (await import('../models/profile.js')).default;
              // Single delete
              if (context && context.record && (context.record.param?._id || context.record.params?._id)) {
                const userId = context.record.param?._id || context.record.params?._id;
                await Profile.deleteOne({ user: userId });
              }
              // Bulk delete
              if (context && context.records && Array.isArray(context.records)) {
                const userIds = context.records.map(r => r.param?._id || r.params?._id).filter(Boolean);
                if (userIds.length > 0) {
                  await Profile.deleteMany({ user: { $in: userIds } });
                }
              }
              return response;
            },
          },
          list: { isAccessible: true },
          show: { isAccessible: true },
        },
      },
    },
    {
      resource: Profile,
      options: {
        properties: {
          _id: { isVisible: false },
          user: { isVisible: { list: false, filter: false, show: true, edit: true } },
          createdAt: { isVisible: false },
          updatedAt: { isVisible: false },
        },
        actions: {
          delete: {
            isAccessible: true,
            after: async (response, request, context) => {
              // Delete the associated user when a profile is deleted
              const userId = context && context.record && (context.record.param?.user || context.record.params?.user);
              if (userId) {
                const User = (await import('../models/user.js')).default;
                await User.deleteOne({ _id: userId });
              }
              // Bulk delete
              if (context && context.records && Array.isArray(context.records)) {
                const userIds = context.records.map(r => r.param?.user || r.params?.user).filter(Boolean);
                if (userIds.length > 0) {
                  const User = (await import('../models/user.js')).default;
                  await User.deleteMany({ _id: { $in: userIds } });
                }
              }
              return response;
            },
          },
        },
      },
    },
    {
      resource: Posts,
      options: {
        properties: {
          _id: { isVisible: false },
          author: { isVisible: { list: false, filter: false, show: true, edit: true } },
          createdAt: { isVisible: false },
          updatedAt: { isVisible: false },
        },
      },
    },
    {
      resource: Events,
      options: {
        properties: {
          _id: { isVisible: false },
          organizer: { isVisible: { list: false, filter: false, show: true, edit: true } },
          createdAt: { isVisible: false },
          updatedAt: { isVisible: false },
        },
      },
    },
    {
      resource: Notification,
      options: {
        properties: {
          _id: { isVisible: false },
          recipient: { isVisible: { list: false, filter: false, show: true, edit: true } },
          sender: { isVisible: { list: false, filter: false, show: true, edit: true } },
          createdAt: { isVisible: false },
          updatedAt: { isVisible: false },
        },
      },
    },
    {
      resource: Subscription,
      options: {
        properties: {
          _id: { isVisible: false },
          user: { isVisible: { list: false, filter: false, show: true, edit: true } },
          createdAt: { isVisible: false },
          updatedAt: { isVisible: false },
        },
      },
    },
    {
      resource: Transaction,
      options: {
        properties: {
          _id: { isVisible: false },
          user: { isVisible: { list: false, filter: false, show: true, edit: true } },
          createdAt: { isVisible: false },
          updatedAt: { isVisible: false },
        },
      },
    },
    {
      resource: BlacklistedToken,
      options: {
        properties: {
          _id: { isVisible: false },
          // Show user email in list/show by populating userId
          userId: {
            reference: 'User',
            isVisible: { list: true, filter: true, show: true, edit: true },
            label: 'User Email',
            components: undefined,
          },
          token: { isVisible: { list: false, filter: false, show: true, edit: false } },
          expiresAt: { isVisible: { list: false, filter: false, show: true, edit: false } },
          createdAt: { isVisible: false },
          updatedAt: { isVisible: false },
        },
        actions: {
          new: {
            before: async (request) => {
              if (request.payload && request.payload.email) {
                // Find user by email and use their refreshToken and _id
                const user = await User.findOne({ email: request.payload.email });
                if (!user || !user.refreshToken) {
                  throw new Error('User not found or user has no refresh token');
                }
                // Set expiresAt to now + refreshExpiresIn
                const env = (await import('../utils/consts.js')).default;
                const parseTimeString = (await import('../utils/helpers.js')).parseTimeString;
                const expiresInMs = parseTimeString(env.jwt.refreshExpiresIn);
                const expiresAt = new Date(Date.now() + expiresInMs);
                request.payload = {
                  token: user.refreshToken,
                  userId: user._id,
                  expiresAt
                };
              }
              return request;
            },
          },
          edit: {
            before: async (request) => {
              if (request.payload && request.payload.email) {
                request.payload = { email: request.payload.email };
              }
              return request;
            },
          },
        },
      },
    },
  ],
  rootPath: '/admin',
  branding: {
    companyName: 'Reva Admin',
    softwareBrothers: false,
  },
});

import bcrypt from 'bcrypt';

const adminRouter = AdminJSExpress.buildAuthenticatedRouter(
  adminJs,
  {
    authenticate: async (email, password) => {
      // Find user with isAdmin true
      const user = await User.findOne({ email, isAdmin: true });
      if (!user) return null;
      // Compare password (mpin field is used for user auth, but for admin panel, use password field or mpin)
      // If you want to use mpin as admin password:
      const isMatch = await user.compareMpin(password);
      if (!isMatch) return null;
      return { email: user.email, id: user._id };
    },
    cookiePassword: process.env.ADMIN_COOKIE_SECRET || 'supersecret',
  }
);

export { adminJs, adminRouter };

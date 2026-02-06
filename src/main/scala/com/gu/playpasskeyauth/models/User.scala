package com.gu.playpasskeyauth.models

trait User[U] {
  extension (u: U) {
    def id: UserId
    def displayName: String
  }
}

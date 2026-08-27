package com.nivra.agent.models

/** Lifecycle state of a locally queued event, tracked for reliability metrics. */
enum class EventState { PENDING, SENDING, SENT, FAILED }

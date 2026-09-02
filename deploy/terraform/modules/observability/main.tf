# Observability (PLAN §16, D-25): ADOT config parameter, dashboards
# (API/git/pipeline/security, §16.2), the §16.3 page alarms, and SNS routing.

data "aws_caller_identity" "current" {}

# --- ADOT collector config (consumed by ecs-service sidecars) --------------

resource "aws_ssm_parameter" "adot_config" {
  name        = "/agentry/${var.environment}/adot-collector-config"
  description = "ADOT collector config for agentry ECS sidecars (§16)."
  type        = "String"
  tier        = "Advanced"
  value       = file("${path.module}/adot-collector-config.yaml")
  tags        = var.tags
}

# Shared metrics log group the awsemf exporter writes EMF to.
resource "aws_cloudwatch_log_group" "metrics" {
  name              = "/agentry/metrics"
  retention_in_days = 30
  tags              = var.tags
}

# --- SNS routing: page vs ticket (§16.3) -----------------------------------

resource "aws_sns_topic" "page" {
  name = "${var.name}-page"
  tags = var.tags
}

resource "aws_sns_topic" "ticket" {
  name = "${var.name}-ticket"
  tags = var.tags
}

data "aws_iam_policy_document" "sns_publish" {
  statement {
    sid       = "AllowServicesPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.page.arn, aws_sns_topic.ticket.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "page" {
  arn    = aws_sns_topic.page.arn
  policy = data.aws_iam_policy_document.sns_publish.json
}

resource "aws_sns_topic_policy" "ticket" {
  arn    = aws_sns_topic.ticket.arn
  policy = data.aws_iam_policy_document.sns_publish.json
}

resource "aws_sns_topic_subscription" "page" {
  count     = length(var.page_subscriptions)
  topic_arn = aws_sns_topic.page.arn
  protocol  = var.page_subscriptions[count.index].protocol
  endpoint  = var.page_subscriptions[count.index].endpoint
}

resource "aws_sns_topic_subscription" "ticket" {
  count     = length(var.ticket_subscriptions)
  topic_arn = aws_sns_topic.ticket.arn
  protocol  = var.ticket_subscriptions[count.index].protocol
  endpoint  = var.ticket_subscriptions[count.index].endpoint
}

# --- Alarm: API availability burn (5xx / requests > SLO) --------------------

resource "aws_cloudwatch_metric_alarm" "availability_burn" {
  count               = var.app_alb_arn_suffix == null ? 0 : 1
  alarm_name          = "${var.name}-availability-burn"
  alarm_description   = "API 5xx ratio breaching the 99.9% SLO (§16.1/§16.3)."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  threshold           = var.availability_error_ratio
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.page.arn]
  ok_actions          = [aws_sns_topic.page.arn]

  metric_query {
    id          = "ratio"
    expression  = "errors / requests"
    label       = "5xx ratio"
    return_data = true
  }

  metric_query {
    id = "errors"
    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "HTTPCode_ELB_5XX_Count"
      dimensions  = { LoadBalancer = var.app_alb_arn_suffix }
      period      = 60
      stat        = "Sum"
    }
  }

  metric_query {
    id = "requests"
    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "RequestCount"
      dimensions  = { LoadBalancer = var.app_alb_arn_suffix }
      period      = 60
      stat        = "Sum"
    }
  }

  tags = var.tags
}

# --- Alarm: River queue age > 15 min ---------------------------------------

resource "aws_cloudwatch_metric_alarm" "queue_age" {
  alarm_name          = "${var.name}-queue-age"
  alarm_description   = "A River queue's oldest job exceeds 15 min (§16.3)."
  namespace           = var.metrics_namespace
  metric_name         = "QueueAgeSeconds"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.queue_age_seconds_threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.page.arn]
  tags                = var.tags
}

# --- Alarm: scan pipeline error rate > 5% ----------------------------------

resource "aws_cloudwatch_metric_alarm" "scan_error_rate" {
  alarm_name          = "${var.name}-scan-error-rate"
  alarm_description   = "Scan pipeline stage error rate above 5% (§16.3)."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  threshold           = var.scan_error_rate_threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.page.arn]

  metric_query {
    id          = "rate"
    expression  = "errors / runs"
    label       = "scan error rate"
    return_data = true
  }

  metric_query {
    id = "errors"
    metric {
      namespace   = var.metrics_namespace
      metric_name = "ScanStageErrors"
      period      = 300
      stat        = "Sum"
    }
  }

  metric_query {
    id = "runs"
    metric {
      namespace   = var.metrics_namespace
      metric_name = "ScanStageRuns"
      period      = 300
      stat        = "Sum"
    }
  }

  tags = var.tags
}

# --- Alarm: RDS failover (EventBridge, not a metric) -----------------------

resource "aws_cloudwatch_event_rule" "rds_failover" {
  count       = var.rds_instance_id == null ? 0 : 1
  name        = "${var.name}-rds-failover"
  description = "RDS Multi-AZ failover events (§16.3)."
  event_pattern = jsonencode({
    source      = ["aws.rds"]
    detail-type = ["RDS DB Instance Event"]
    detail = {
      EventCategories  = ["failover"]
      SourceIdentifier = [var.rds_instance_id]
    }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "rds_failover" {
  count     = var.rds_instance_id == null ? 0 : 1
  rule      = aws_cloudwatch_event_rule.rds_failover[0].name
  target_id = "page"
  arn       = aws_sns_topic.page.arn
}

# --- Alarm: KMS Sign anomaly (T-09) via CloudTrail data events -------------

resource "aws_cloudwatch_log_metric_filter" "kms_sign" {
  count          = var.cloudtrail_log_group_name == null ? 0 : 1
  name           = "${var.name}-kms-sign"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{ ($.eventSource = \"kms.amazonaws.com\") && ($.eventName = \"Sign\") }"

  metric_transformation {
    name          = "KmsSignCount"
    namespace     = "Agentry/Security"
    value         = "1"
    default_value = "0"
  }
}

# Fail-open events (agentry#33): the audit archive dropping a record, or
# S7 publishing a version without an OSV lookup. Each is a deliberate
# choice to continue rather than stop; the alarm makes the choice visible
# as a ticket rather than a log line. Any occurrence in an hour tickets.
resource "aws_cloudwatch_metric_alarm" "fail_open_events" {
  alarm_name          = "${var.name}-fail-open-events"
  alarm_description   = "A fail-open path ran: audit archive drop or OSV not checked (§16.3 ticket, agentry#33)."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ticket.arn]
  namespace           = var.metrics_namespace
  metric_name         = "FailOpenEvents"
  period              = 3600
  statistic           = "Sum"
}

resource "aws_cloudwatch_metric_alarm" "kms_sign_anomaly" {
  count               = var.cloudtrail_log_group_name == null ? 0 : 1
  alarm_name          = "${var.name}-kms-sign-anomaly"
  alarm_description   = var.signing_key_id == null ? "Anomalous kms:Sign volume on the attestation key (T-09)." : "Anomalous kms:Sign volume on attestation key ${var.signing_key_id} (T-09)."
  comparison_operator = "GreaterThanUpperThreshold"
  evaluation_periods  = 2
  threshold_metric_id = "ad"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.page.arn]

  metric_query {
    id          = "m"
    return_data = true
    metric {
      namespace   = "Agentry/Security"
      metric_name = "KmsSignCount"
      period      = 300
      stat        = "Sum"
    }
  }

  metric_query {
    id          = "ad"
    expression  = "ANOMALY_DETECTION_BAND(m, 3)"
    label       = "expected"
    return_data = true
  }

  tags = var.tags
}

# --- Alarm: WAF block spike ------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "waf_block_spike" {
  count               = var.web_acl_metric_name == null ? 0 : 1
  alarm_name          = "${var.name}-waf-block-spike"
  alarm_description   = "Spike in WAF-blocked requests — possible attack wave (§16.3)."
  comparison_operator = "GreaterThanUpperThreshold"
  evaluation_periods  = 2
  threshold_metric_id = "ad"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.page.arn]

  metric_query {
    id          = "m"
    return_data = true
    metric {
      namespace   = "AWS/WAFV2"
      metric_name = "BlockedRequests"
      dimensions  = { WebACL = var.web_acl_metric_name, Region = var.aws_region, Rule = "ALL" }
      period      = 300
      stat        = "Sum"
    }
  }

  metric_query {
    id          = "ad"
    expression  = "ANOMALY_DETECTION_BAND(m, 4)"
    label       = "expected"
    return_data = true
  }

  tags = var.tags
}

# --- Dashboards (§16.2) ----------------------------------------------------

resource "aws_cloudwatch_dashboard" "api" {
  count          = var.app_alb_arn_suffix == null ? 0 : 1
  dashboard_name = "${var.name}-api"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", x = 0, y = 0, width = 12, height = 6,
        properties = {
          title  = "API RED — request count / 5xx",
          region = var.aws_region,
          view   = "timeSeries",
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", var.app_alb_arn_suffix],
            ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", var.app_alb_arn_suffix],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6,
        properties = {
          title   = "API latency (p99) — SLO < 300ms",
          region  = var.aws_region,
          view    = "timeSeries",
          metrics = [["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", var.app_alb_arn_suffix, { stat = "p99" }]]
        }
      },
    ]
  })
}

resource "aws_cloudwatch_dashboard" "git" {
  count          = var.git_alb_arn_suffix == null ? 0 : 1
  dashboard_name = "${var.name}-git"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", x = 0, y = 0, width = 12, height = 6,
        properties = {
          title   = "git op concurrency (River)",
          region  = var.aws_region,
          view    = "timeSeries",
          metrics = [[var.metrics_namespace, "GitOpConcurrency"]]
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6,
        properties = {
          title   = "git clone first-byte latency — SLO p95 < 2s",
          region  = var.aws_region,
          view    = "timeSeries",
          metrics = [[var.metrics_namespace, "GitCloneFirstByteSeconds", { stat = "p95" }]]
        }
      },
    ]
  })
}

resource "aws_cloudwatch_dashboard" "pipeline" {
  dashboard_name = "${var.name}-pipeline"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", x = 0, y = 0, width = 12, height = 6,
        properties = {
          title   = "Publish funnel — submitted -> verdict states/hour (§16.2)",
          region  = var.aws_region,
          view    = "timeSeries",
          stacked = true,
          metrics = [
            [var.metrics_namespace, "PublishSubmitted"],
            [var.metrics_namespace, "PublishVerdictClean"],
            [var.metrics_namespace, "PublishVerdictReview"],
            [var.metrics_namespace, "PublishVerdictBlocked"],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6,
        properties = {
          title  = "Scan stage durations + judge cost",
          region = var.aws_region,
          view   = "timeSeries",
          metrics = [
            [var.metrics_namespace, "ScanStageDurationSeconds", { stat = "p95" }],
            [var.metrics_namespace, "JudgeCostCents"],
          ]
        }
      },
      {
        type = "metric", x = 0, y = 6, width = 12, height = 6,
        properties = {
          title  = "Queue depth / age per River queue",
          region = var.aws_region,
          view   = "timeSeries",
          metrics = [
            [var.metrics_namespace, "QueueDepth"],
            [var.metrics_namespace, "QueueAgeSeconds", { stat = "Maximum" }],
          ]
        }
      },
    ]
  })
}

resource "aws_cloudwatch_dashboard" "security" {
  dashboard_name = "${var.name}-security"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", x = 0, y = 0, width = 12, height = 6,
        properties = {
          title   = "S-stage hit rates (S3 spike = attack-wave signal, §16.2)",
          region  = var.aws_region,
          view    = "timeSeries",
          metrics = [[var.metrics_namespace, "ScanStageHits", { stat = "Sum" }]]
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6,
        properties = {
          title  = "Verdict mix",
          region = var.aws_region,
          view   = "timeSeries",
          metrics = [
            [var.metrics_namespace, "PublishVerdictClean"],
            [var.metrics_namespace, "PublishVerdictReview"],
            [var.metrics_namespace, "PublishVerdictBlocked"],
          ]
        }
      },
      {
        type = "metric", x = 0, y = 6, width = 24, height = 6,
        properties = {
          title  = "KMS Sign volume (T-09) + WAF blocked requests",
          region = var.aws_region,
          view   = "timeSeries",
          metrics = [
            ["Agentry/Security", "KmsSignCount", { stat = "Sum" }],
            ["AWS/WAFV2", "BlockedRequests", "WebACL", coalesce(var.web_acl_metric_name, "none"), "Region", var.aws_region, "Rule", "ALL"],
          ]
        }
      },
    ]
  })
}

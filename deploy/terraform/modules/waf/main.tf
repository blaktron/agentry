# Two WAFv2 web ACLs (PLAN §13.5):
#   web/API — AWS managed core + known-bad-inputs + per-IP rate rule.
#   git     — managed core with body-inspection rules set to COUNT (they
#             false-positive on git packfiles) + per-IP rate rule.

# ===========================================================================
# web / API
# ===========================================================================

resource "aws_wafv2_web_acl" "web" {
  name  = "${var.name}-web"
  scope = var.scope

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedCommon"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-web-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedKnownBadInputs"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-web-badinputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "PerIPRate"
    priority = 3
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.web_rate_limit
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-web-rate"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-web"
    sampled_requests_enabled   = true
  }

  tags = var.tags
}

# ===========================================================================
# git hostname
# ===========================================================================

resource "aws_wafv2_web_acl" "git" {
  name  = "${var.name}-git"
  scope = var.scope

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedCommonGitTuned"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        # Body-inspection rules false-positive on packfiles -> COUNT, not block.
        dynamic "rule_action_override" {
          for_each = toset(var.git_body_inspection_excluded_rules)
          content {
            name = rule_action_override.value
            action_to_use {
              count {}
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-git-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "PerIPRate"
    priority = 2
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.git_rate_limit
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-git-rate"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-git"
    sampled_requests_enabled   = true
  }

  tags = var.tags
}

﻿namespace Xpass
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            DataGridViewCellStyle dataGridViewCellStyle1 = new DataGridViewCellStyle();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            masterPasswdLabel = new Label();
            masterPasswdTextBox = new TextBox();
            showPasswdCheckBox = new CheckBox();
            selectFilesButton = new Button();
            selectDirButton = new Button();
            decryptButton = new Button();
            pathRichTextBox = new RichTextBox();
            notifyIcon1 = new NotifyIcon(components);
            openFileDialog1 = new OpenFileDialog();
            folderBrowserDialog1 = new FolderBrowserDialog();
            dataGridView1 = new DataGridView();
            Column2 = new DataGridViewTextBoxColumn();
            Column3 = new DataGridViewTextBoxColumn();
            Column4 = new DataGridViewTextBoxColumn();
            Column5 = new DataGridViewTextBoxColumn();
            Column6 = new DataGridViewTextBoxColumn();
            button1 = new Button();
            ((System.ComponentModel.ISupportInitialize)dataGridView1).BeginInit();
            SuspendLayout();
            // 
            // masterPasswdLabel
            // 
            masterPasswdLabel.AutoSize = true;
            masterPasswdLabel.Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
            masterPasswdLabel.Location = new Point(12, 131);
            masterPasswdLabel.Name = "masterPasswdLabel";
            masterPasswdLabel.Size = new Size(56, 17);
            masterPasswdLabel.TabIndex = 0;
            masterPasswdLabel.Text = "主密码：";
            // 
            // masterPasswdTextBox
            // 
            masterPasswdTextBox.Location = new Point(74, 128);
            masterPasswdTextBox.Name = "masterPasswdTextBox";
            masterPasswdTextBox.PasswordChar = '*';
            masterPasswdTextBox.PlaceholderText = "如果设置了主密码请输入";
            masterPasswdTextBox.Size = new Size(420, 23);
            masterPasswdTextBox.TabIndex = 5;
            // 
            // showPasswdCheckBox
            // 
            showPasswdCheckBox.AutoSize = true;
            showPasswdCheckBox.ForeColor = SystemColors.ControlDarkDark;
            showPasswdCheckBox.Location = new Point(500, 131);
            showPasswdCheckBox.Name = "showPasswdCheckBox";
            showPasswdCheckBox.Size = new Size(75, 21);
            showPasswdCheckBox.TabIndex = 2;
            showPasswdCheckBox.Text = "显示密码";
            showPasswdCheckBox.UseVisualStyleBackColor = true;
            showPasswdCheckBox.CheckedChanged += showPasswdCheckBox_CheckedChanged;
            // 
            // selectFilesButton
            // 
            selectFilesButton.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold, GraphicsUnit.Point);
            selectFilesButton.ForeColor = Color.DodgerBlue;
            selectFilesButton.Location = new Point(12, 11);
            selectFilesButton.Name = "selectFilesButton";
            selectFilesButton.Size = new Size(75, 50);
            selectFilesButton.TabIndex = 3;
            selectFilesButton.Text = "选择文件";
            selectFilesButton.UseVisualStyleBackColor = true;
            selectFilesButton.Click += SelectFilesButton_Click;
            // 
            // selectDirButton
            // 
            selectDirButton.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold, GraphicsUnit.Point);
            selectDirButton.ForeColor = Color.DodgerBlue;
            selectDirButton.Location = new Point(12, 67);
            selectDirButton.Name = "selectDirButton";
            selectDirButton.Size = new Size(75, 50);
            selectDirButton.TabIndex = 4;
            selectDirButton.Text = "选择目录";
            selectDirButton.UseVisualStyleBackColor = true;
            selectDirButton.Click += SelectDirButton_Click;
            // 
            // decryptButton
            // 
            decryptButton.BackColor = Color.DeepSkyBlue;
            decryptButton.Font = new Font("Microsoft YaHei UI", 24F, FontStyle.Bold, GraphicsUnit.Point);
            decryptButton.Location = new Point(566, 12);
            decryptButton.Name = "decryptButton";
            decryptButton.Size = new Size(106, 106);
            decryptButton.TabIndex = 5;
            decryptButton.Text = "解密";
            decryptButton.UseVisualStyleBackColor = false;
            decryptButton.Click += DecryptButton_Click;
            // 
            // pathRichTextBox
            // 
            pathRichTextBox.Location = new Point(93, 12);
            pathRichTextBox.Name = "pathRichTextBox";
            pathRichTextBox.ReadOnly = true;
            pathRichTextBox.Size = new Size(467, 105);
            pathRichTextBox.TabIndex = 6;
            pathRichTextBox.Text = "";
            // 
            // notifyIcon1
            // 
            notifyIcon1.Text = "notifyIcon1";
            notifyIcon1.Visible = true;
            // 
            // openFileDialog1
            // 
            openFileDialog1.Filter = "会话文件(*.xsh)|*.xsh|所有文件(*.*)|*.*";
            openFileDialog1.Multiselect = true;
            openFileDialog1.Title = "选择会话文件";
            // 
            // dataGridView1
            // 
            dataGridView1.AllowUserToAddRows = false;
            dataGridView1.AllowUserToDeleteRows = false;
            dataGridView1.AllowUserToOrderColumns = true;
            dataGridView1.AllowUserToResizeRows = false;
            dataGridView1.BackgroundColor = Color.White;
            dataGridView1.BorderStyle = BorderStyle.Fixed3D;
            dataGridViewCellStyle1.Alignment = DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle1.BackColor = SystemColors.Control;
            dataGridViewCellStyle1.Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Bold, GraphicsUnit.Point);
            dataGridViewCellStyle1.ForeColor = SystemColors.WindowText;
            dataGridViewCellStyle1.Padding = new Padding(0, 5, 0, 5);
            dataGridViewCellStyle1.SelectionBackColor = SystemColors.Highlight;
            dataGridViewCellStyle1.SelectionForeColor = SystemColors.HighlightText;
            dataGridViewCellStyle1.WrapMode = DataGridViewTriState.True;
            dataGridView1.ColumnHeadersDefaultCellStyle = dataGridViewCellStyle1;
            dataGridView1.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            dataGridView1.Columns.AddRange(new DataGridViewColumn[] { Column2, Column3, Column4, Column5, Column6 });
            dataGridView1.Location = new Point(12, 161);
            dataGridView1.Name = "dataGridView1";
            dataGridView1.ReadOnly = true;
            dataGridView1.RowHeadersWidth = 30;
            dataGridView1.RowHeadersWidthSizeMode = DataGridViewRowHeadersWidthSizeMode.DisableResizing;
            dataGridView1.RowTemplate.Height = 25;
            dataGridView1.Size = new Size(660, 388);
            dataGridView1.TabIndex = 7;
            dataGridView1.RowPostPaint += dataGridView1_RowPostPaint;
            // 
            // Column2
            // 
            Column2.HeaderText = "会话路径";
            Column2.Name = "Column2";
            Column2.ReadOnly = true;
            // 
            // Column3
            // 
            Column3.HeaderText = "主机地址";
            Column3.Name = "Column3";
            Column3.ReadOnly = true;
            // 
            // Column4
            // 
            Column4.HeaderText = "端口";
            Column4.Name = "Column4";
            Column4.ReadOnly = true;
            // 
            // Column5
            // 
            Column5.HeaderText = "用户名";
            Column5.Name = "Column5";
            Column5.ReadOnly = true;
            // 
            // Column6
            // 
            Column6.HeaderText = "密码";
            Column6.Name = "Column6";
            Column6.ReadOnly = true;
            // 
            // button1
            // 
            button1.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold, GraphicsUnit.Point);
            button1.Location = new Point(600, 123);
            button1.Name = "button1";
            button1.Size = new Size(72, 32);
            button1.TabIndex = 8;
            button1.Text = "导出";
            button1.UseVisualStyleBackColor = true;
            button1.Click += button1_Click;
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(7F, 17F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(684, 561);
            Controls.Add(button1);
            Controls.Add(dataGridView1);
            Controls.Add(pathRichTextBox);
            Controls.Add(decryptButton);
            Controls.Add(selectDirButton);
            Controls.Add(selectFilesButton);
            Controls.Add(showPasswdCheckBox);
            Controls.Add(masterPasswdTextBox);
            Controls.Add(masterPasswdLabel);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            Icon = (Icon)resources.GetObject("$this.Icon");
            MaximizeBox = false;
            Name = "Form1";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "Xpass";
            ((System.ComponentModel.ISupportInitialize)dataGridView1).EndInit();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Label masterPasswdLabel;
        private TextBox masterPasswdTextBox;
        private CheckBox showPasswdCheckBox;
        private Button selectFilesButton;
        private Button selectDirButton;
        private Button decryptButton;
        private RichTextBox pathRichTextBox;
        private NotifyIcon notifyIcon1;
        private OpenFileDialog openFileDialog1;
        private FolderBrowserDialog folderBrowserDialog1;
        private DataGridView dataGridView1;
        private DataGridViewTextBoxColumn Column2;
        private DataGridViewTextBoxColumn Column3;
        private DataGridViewTextBoxColumn Column4;
        private DataGridViewTextBoxColumn Column5;
        private DataGridViewTextBoxColumn Column6;
        private Button button1;
    }
}
